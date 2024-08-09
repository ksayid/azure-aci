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
	"os"
	"strings"

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
	k8spersistentvolumes      = ""
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
				fmt.Fprintln(os.Stderr, "Usage podspec-to-arm <input-file-name> [--output-file-name <output file>] [--print-json]")
				os.Exit(1)
			}

			fileName := args[0]

			// create pod object from podspec yaml file
			file, err := os.ReadFile(fileName)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error reading file: ", err)
				os.Exit(1)
			}

			pod := v1.Pod{}
			err = yaml.Unmarshal(file, &pod)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error unmarshalling YAML: ", err)
				os.Exit(1)
			}
			aciMocks := createNewACIMock()
			provider, err := createTestProvider(aciMocks, NewMockConfigMapLister(),
				NewMockSecretLister(), NewMockPodLister(), nil)
			if err != nil {
				fmt.Fprintln(os.Stderr, "got error init provider")
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			// read secrets from file
			secretsMap := map[string]corev1.Secret{}
			if k8secrets != "" {
				secretsfile, err := os.ReadFile(k8secrets)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error reading secrets file:", err)
					os.Exit(1)
				}
				err = yaml.Unmarshal([]byte(secretsfile), &secretsMap)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error unmarshalling secrets:", err)
					fmt.Fprintf(os.Stderr, "Make sure the file is of the format: \n<secret-name>:\n  apiVersion: v1\n  kind: Secret\n  metadata\n    name: <secret-name>\n  data:\n    <key>: <value>\n")
					os.Exit(1)
				}

				// fill in values in pod with secrets data
				for i := range pod.Spec.Containers {
					container := &pod.Spec.Containers[i]
					for j := range container.Env {
						envVar := &container.Env[j]
						if envVar.ValueFrom != nil && envVar.ValueFrom.SecretKeyRef != nil {
							secretName := envVar.ValueFrom.SecretKeyRef.Name
							key := envVar.ValueFrom.SecretKeyRef.Key
							secret, ok := secretsMap[secretName]
							if !ok {
								fmt.Fprintf(os.Stderr, "Secret %s not found in secrets file\n", secretName)
								os.Exit(1)
							}
							val, ok := secret.Data[key]
							if !ok {
								fmt.Fprintf(os.Stderr, "Key %s not found in secret %s\n", key, secretName)
								os.Exit(1)
							}

							// remove trailing newline characters
							envVar.Value = strings.TrimRight(string(val), "\r\n")
						}
					}
				}
			}

			// read configmaps from file
			configsMap := map[string]corev1.ConfigMap{}
			if k8configmaps != "" {
				configmapfile, err := os.ReadFile(k8configmaps)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error reading configmaps file:", err)
					os.Exit(1)
				}
				err = yaml.Unmarshal([]byte(configmapfile), &configsMap)

				if err != nil {
					fmt.Fprintln(os.Stderr, "Error unmarshalling configmaps:", err)
					fmt.Fprintf(os.Stderr, "Make sure the file is of the format: \n<configmap-name>:\n  apiVersion: v1\n  kind: ConfigMap\n  metadata\n    name: <configmap-name>\n  data:\n    <key>: <value>\n")
					os.Exit(1)
				}

				// fill in values in pod with configmaps data
				for i := range pod.Spec.Containers {
					container := &pod.Spec.Containers[i]
					for j := range container.Env {
						envVar := &container.Env[j]
						if envVar.ValueFrom != nil && envVar.ValueFrom.ConfigMapKeyRef != nil {
							configName := envVar.ValueFrom.ConfigMapKeyRef.Name
							key := envVar.ValueFrom.ConfigMapKeyRef.Key
							config, ok := configsMap[configName]
							if !ok {
								fmt.Fprintf(os.Stderr, "ConfigMap %s not found in configmaps file\n", configName)
								os.Exit(1)
							}
							val, ok := config.Data[key]
							if !ok {
								fmt.Fprintf(os.Stderr, "Key %s not found in configmap %s\n", key, configName)
								os.Exit(1)
							}
							envVar.Value = string(val)
						}
					}
				}
			}

			type volumeMount struct {
				volumename string
				mountpath  string
				readonly   bool
			}

			newVolumeMounts := []volumeMount{}

			persistentVolumes := map[string]corev1.PersistentVolume{}
			if k8spersistentvolumes != "" {
				pvfile, err := os.ReadFile(k8spersistentvolumes)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error reading persistent volumes file:", err)
					os.Exit(1)
				}
				err = yaml.Unmarshal([]byte(pvfile), &persistentVolumes)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error unmarshalling persistent volumes:", err)
					fmt.Fprintf(os.Stderr, "Make sure the file is of the format: \n<pv-name>:\n  apiVersion: v1\n  kind: PersistentVolume\n  metadata\n    name: <pv-name>\n  spec:\n    capacity:\n      storage: <storage-size>\n    accessModes:\n      - <access-mode>\n    persistentVolumeReclaimPolicy: <reclaim-policy>\n    storageClassName: <storage-class>\n    volumeMode: <volume-mode>\n    azureDisk:\n      kind: Managed\n      diskName: <disk-name>\n      diskURI: <disk-uri>\n      cachingMode: <caching-mode>\n      fsType: <fs-type>\n      readOnly: <read-only>\n")
					os.Exit(1)
				}
				// fill in values in pod with persistent volumes data
				for i := range pod.Spec.Containers {
					container := &pod.Spec.Containers[i]
					for j := range container.VolumeMounts {
						tempVolumeMount := &container.VolumeMounts[j]
						pvName := tempVolumeMount.Name
						pv, ok := persistentVolumes[pvName]
						if !ok {
							fmt.Fprintf(os.Stderr, "Persistent Volume %s not found in persistent volumes file\n", pvName)
							os.Exit(1)
						}

						// these mounts are spoofed as emptydirs to behave correctly in the policy
						newVolumeMounts = append(newVolumeMounts, volumeMount{
							volumename: pvName,
							mountpath:  "sandbox:///tmp/atlas/emptydir/.+",
							readonly:   *(pv.Spec.AzureDisk.ReadOnly),
						})
					}
				}
			}


			//provider := azproviderv2.ACIProvider{}
			//provider.enabledFeatures = featureflag.InitFeatureFlag(context.Background())
			// create container group
			cg, err := provider.CreatePodData(context.Background(), &pod, secretsMap, configsMap)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error creating pod data", err)
				os.Exit(1)
			}
			// fill in namespace if not present
			if pod.Namespace == "" {
				pod.Namespace = "default"
			}
			cgName := fmt.Sprintf("%s-%s", pod.Namespace, pod.Name)
			cgType := "Microsoft.ContainerInstance/containerGroups"

			// NOTE: to be a valid ARM template, there should be an apiVersion
			// But this is not necessary for policy generation
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

			// inject volume mounts
			volumeMounts := []volumeMount{
				{"kube-api-access-123", "/var/run/secrets/kubernetes.io/serviceaccount", false},
				{"kube-hosts-123", "/etc/hosts", false},
				{"kube-termination-log-123", "/dev/termination-log", false},
			}

			// combine newVolumeMounts with existing volume mounts
			volumeMounts = append(volumeMounts, newVolumeMounts...)

			for _, vm := range volumeMounts {
				injectVolumeMount(&containerGroup, vm.volumename, vm.mountpath, vm.readonly)
			}

			// create ARM object to encapsulate this cg object with container group resource
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
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
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
				fmt.Fprintln(os.Stderr, "Error creating output file:", err)
				os.Exit(1)
			}
			defer f.Close()
			n, err := f.Write([]byte(outputjson))
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error writing to output file:", err)
				os.Exit(1)
			}
			fmt.Printf("Written %d bytes to file %s\n", n, outFileName)
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
	err := json.Unmarshal([]byte(k8EnvVarsString), &k8EnvVars)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error unmarshalling environment variables:", err)
		os.Exit(1)
	}
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
