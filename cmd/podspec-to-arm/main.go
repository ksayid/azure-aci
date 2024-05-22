// Copyright © 2017 The virtual-kubelet authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	yaml "sigs.k8s.io/yaml"

	azaciv2 "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance/v2"
	"github.com/spf13/cobra"
	"github.com/virtual-kubelet/azure-aci/pkg/auth"
	azproviderv2 "github.com/virtual-kubelet/azure-aci/pkg/provider"
	"github.com/virtual-kubelet/virtual-kubelet/node/nodeutil"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"regexp"
)

var (
	outFileName        string = "arm-template.json"
	printJson          bool   = false
	listenPort         int32  = 10250
	cfgPath            string = ""
	clusterDomain      string = ""
	kubeConfigPath            = os.Getenv("KUBECONFIG")
	azConfig                  = auth.Config{}
	k8secrets                 = ""
	k8configmaps              = ""
	K8Port                    = "tcp://10.0.0.1:443"
	K8PortTCP                 = "tcp://10.0.0.1:443"
	K8PortTCPProto            = "tcp"
	K8PortTCPPort             = "443"
	K8PortTCPAddr             = "10.0.0.1"
	K8ServiceHost             = "10.0.0.1"
	K8ServicePort             = "443"
	K8ServicePortHTTPS        = "443"
)

type ARMSpec struct {
	Schema         string                   `json:"$schema,omitempty"`
	ContentVersion string                   `json:"contentVersion,omitempty"`
	Variables      []any                    `json:"variables,omitempty"`
	Resources      []azaciv2.ContainerGroup `json:"resources,omitempty"`
}

func main() {

	desc := "convert virtual kubelet pod spec to ACI ARM deployment template"
	cmd := &cobra.Command{
		Use:   "convert",
		Short: desc,
		Long:  desc,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Println("Usage podspec-to-arm <input-file-name> [--output-file-name <output file>] [--print-json]")
				return
			}

			fileName := args[0]

			// create pod object from podspec yaml file
			file, err := ioutil.ReadFile(fileName)
			if err != nil {
				fmt.Println(err)
				return
			}

			pod := v1.Pod{}
			_ = yaml.Unmarshal(file, &pod)

			aciMocks := createNewACIMock()
			provider, err := createTestProvider(aciMocks, NewMockConfigMapLister(),
				NewMockSecretLister(), NewMockPodLister(), nil)
			if err != nil {
				fmt.Println("got error init provider")
				fmt.Println(err)
			}

			// read secrets from file
			secretsMap := map[string]corev1.Secret{}
			if k8secrets != "" {
				secretsfile, err := ioutil.ReadFile(k8secrets)
				if err != nil {
					fmt.Println(err)
					return
				}
				err = yaml.Unmarshal([]byte(secretsfile), &secretsMap)
				if err != nil {
					fmt.Println("error unmarshalling secrets map")
					fmt.Println(err)
					return
				}
			}

			// read configmaps from file
			configsMap := map[string]corev1.ConfigMap{}
			if k8configmaps != "" {
				configmapfile, err := ioutil.ReadFile(k8configmaps)
				if err != nil {
					fmt.Println(err)
					return
				}
				err = yaml.Unmarshal([]byte(configmapfile), &configsMap)

				if err != nil {
					fmt.Println("error unmarshalling config map")
					fmt.Println(err)
					return
				}
			}

			//provider := azproviderv2.ACIProvider{}
			//provider.enabledFeatures = featureflag.InitFeatureFlag(context.Background())
			// create container group
			cg, err := provider.CreatePodData(context.Background(), &pod, secretsMap, configsMap)
			if err != nil {
				fmt.Println(err)
			}
			cgName := fmt.Sprintf("%s-%s", pod.Namespace, pod.Name)
			cgType := "Microsoft.ContainerInstance/containerGroups"

			containerGroup := azaciv2.ContainerGroup{
				Properties: cg.Properties,
				Name:       &cgName,
				Identity:   cg.Identity,
				Location:   cg.Location,
				Tags:       cg.Tags,
				ID:         cg.ID,
				Type:       &cgType,
			}

			if containerGroup.Properties.ConfidentialComputeProperties == nil {
				containerGroup.Properties.ConfidentialComputeProperties = &azaciv2.ConfidentialComputeProperties{}
			}

			injectEnvVars(&containerGroup)

			type volumeMount struct {
				volumename string
				mountpath  string
				readonly   bool
			}

			// inject volume mounts
			volumeMounts := []volumeMount{
				{"kube-api-access-123", "/var/run/secrets/kubernetes.io/serviceaccount", false},
				{"kube-hosts-123", "/etc/hosts", false},
				{"kube-termination-log-123", "/dev/termination-log", false},
			}

			for _, vm := range volumeMounts {
				injectVolumeMount(&containerGroup, vm.volumename, vm.mountpath, vm.readonly)
			}

			// create ARM object to encapsulate this cg object with continer group resource
			armTemplate := ARMSpec{
				Schema:         "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
				ContentVersion: "1.0.0.0",
				Variables:      []any{},
				Resources: []azaciv2.ContainerGroup{
					containerGroup,
				},
			}

			arm_json_bytes, err := json.MarshalIndent(armTemplate, "", "\t")
			if err != nil {
				fmt.Println(err)
			}

			outputjson := string(arm_json_bytes)
			// remove emptyDir : null from json that leads to wrong mountpath in policy
			re := regexp.MustCompile(`"emptyDir": null,`)
			outputjson = re.ReplaceAllString(outputjson, "")

			if printJson {
				fmt.Println(outputjson)
			}

			// write output to file
			f, err := os.Create(outFileName)
			if err != nil {
				fmt.Println(err)
				return
			}
			defer f.Close()
			n, err := f.Write([]byte(outputjson))
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Printf("written %d bytes to file %s\n", n, outFileName)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&outFileName, "output-file-name", outFileName, "name of the output file")
	flags.StringVar(&k8secrets, "secrets", k8secrets, "kubernetes secrets filename")
	flags.StringVar(&k8configmaps, "configmaps", k8configmaps, "kubernetes config maps filename")
	flags.StringVar(&K8Port, "kubernetes-port", K8Port, "KUBERNETES_PORT environment variable")
	flags.StringVar(&K8PortTCP, "kubernetes-port-tcp", K8PortTCP, "KUBERNETES_PORT_443_TCP environment variable")
	flags.StringVar(&K8PortTCPProto, "kubernetes-port-tcp-proto", K8PortTCPProto, "KUBERNETES_PORT_443_TCP_PROTO environment variable")
	flags.StringVar(&K8PortTCPPort, "kubernetes-tcp-port", K8PortTCPPort, "KUBERNETES_PORT_443_TCP_PORT environment variable")
	flags.StringVar(&K8PortTCPAddr, "kubernetes-port-tcp-addr", K8PortTCPAddr, "KUBERNETES_PORT_443_TCP_ADDRESS environment variable")
	flags.StringVar(&K8ServiceHost, "kubernetes-service-host", K8ServiceHost, "KUBERNETES_SERVICE_HOST environment variable")
	flags.StringVar(&K8ServicePort, "kubernetes-service-port", K8ServicePort, "KUBERNETES_SERVICE_PORT environment variable")
	flags.StringVar(&K8ServicePortHTTPS, "kubernetes-service-port-https", K8ServicePortHTTPS, "KUBERNETES_SERVICE_PORT_HTTPS environment variable")
	flags.BoolVar(&printJson, "print-json", printJson, "whether or not to print ARM template")

	cmd.Execute()
}

func createNewACIMock() *MockACIProvider {
	return NewMockACIProvider(func(ctx context.Context, region string) ([]*azaciv2.Capabilities, error) {
		gpu := "P100"
		capability := &azaciv2.Capabilities{
			Location: &region,
			Gpu:      &gpu,
		}
		var result []*azaciv2.Capabilities
		result = append(result, capability)
		return result, nil
	})
}

func createTestProvider(aciMocks *MockACIProvider, configMapMocker *MockConfigMapLister, secretMocker *MockSecretLister, podMocker *MockPodLister, kubeClient kubernetes.Interface) (*azproviderv2.ACIProvider, error) {
	ctx := context.TODO()

	err := setAuthConfig()
	if err != nil {
		fmt.Println(err)
		//return nil, err
	}

	if kubeClient == nil {
		kubeClient = fake.NewSimpleClientset()
	}

	err = os.Setenv("ACI_VNET_NAME", "fakevnet")
	if err != nil {
		return nil, err
	}
	//err = os.Setenv("ACI_SUBNET_NAME", "fakevnet")
	//if err != nil {
	//	return nil, err
	//}
	err = os.Setenv("ACI_VNET_RESOURCE_GROUP", "fakerg")
	if err != nil {
		return nil, err
	}
	err = os.Setenv("ACI_RESOURCE_GROUP", "fakerg")
	if err != nil {
		return nil, err
	}
	err = os.Setenv("ACI_REGION", "eastus2euap")
	if err != nil {
		return nil, err
	}

	cfg := nodeutil.ProviderConfig{
		ConfigMaps: configMapMocker,
		Secrets:    secretMocker,
		Pods:       podMocker,
	}

	cfg.Node = &corev1.Node{}

	operatingSystem, osTypeSet := os.LookupEnv("PROVIDER_OPERATING_SYSTEM")

	if !osTypeSet {
		operatingSystem = "Linux"
	}

	cfg.Node.Name = "fakenode"
	cfg.Node.Status.NodeInfo.OperatingSystem = operatingSystem

	provider, err := azproviderv2.NewACIProvider(ctx, "", azConfig, aciMocks, cfg, "fakenode", operatingSystem, "0.0.0.0", 10250, "cluster.local", kubeClient)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

func setAuthConfig() error {
	err := azConfig.SetAuthConfig(context.TODO())
	if err != nil {
		return err
	}
	return nil
}

func injectEnvVars(containergroup *azaciv2.ContainerGroup) {
	k8EnvVarsString := fmt.Sprintf(`[
                {
                  "name": "KUBERNETES_PORT",
                  "value": "%s"
                },
                {
                  "name": "KUBERNETES_PORT_443_TCP",
                  "value": "%s"
                },
                {
                  "name": "KUBERNETES_PORT_443_TCP_PROTO",
                  "value": "%s"
                },
                {
                  "name": "KUBERNETES_PORT_443_TCP_PORT",
                  "value": "%s"
                },
                {
                  "name": "KUBERNETES_PORT_443_TCP_ADDR",
                  "value": "%s"
                },
                {
                  "name": "KUBERNETES_SERVICE_HOST",
                  "value": "%s"
                },
                {
                  "name": "KUBERNETES_SERVICE_PORT",
                  "value": "%s"
                },
                {
                  "name": "KUBERNETES_SERVICE_PORT_HTTPS",
                  "value": "%s"
                }
              ]`, K8Port, K8PortTCP, K8PortTCPProto, K8PortTCPPort, K8PortTCPAddr, K8ServiceHost, K8ServicePort, K8ServicePortHTTPS)
	k8EnvVars := []*azaciv2.EnvironmentVariable{}
	json.Unmarshal([]byte(k8EnvVarsString), &k8EnvVars)
	for i := range containergroup.Properties.Containers {
		container := containergroup.Properties.Containers[i]
		if container.Properties.EnvironmentVariables == nil {
			container.Properties.EnvironmentVariables = []*azaciv2.EnvironmentVariable{}
		}
		container.Properties.EnvironmentVariables = append(container.Properties.EnvironmentVariables, k8EnvVars...)
	}
}

func injectVolumeMount(containergroup *azaciv2.ContainerGroup, volumename string, mountpath string, readonly bool) {
	k8VolumeMount := &azaciv2.VolumeMount{
		Name:      &volumename,
		MountPath: &mountpath,
		ReadOnly:  &readonly,
	}

	k8Volume := &azaciv2.Volume{
		Name:   &volumename,
		EmptyDir: map[string]*string{},
	}

	for i := range containergroup.Properties.Containers {
		container := containergroup.Properties.Containers[i]
		if container.Properties.VolumeMounts == nil {
			container.Properties.VolumeMounts = []*azaciv2.VolumeMount{}
		}
		container.Properties.VolumeMounts = append(container.Properties.VolumeMounts, k8VolumeMount)
	}

	if containergroup.Properties.Volumes == nil {
		containergroup.Properties.Volumes = []*azaciv2.Volume{}
	}
	containergroup.Properties.Volumes = append(containergroup.Properties.Volumes, k8Volume)
}



//TODO:
//2. Better error messages -> check various failures and throw better messages
