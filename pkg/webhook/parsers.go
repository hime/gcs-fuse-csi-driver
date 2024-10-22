/*
Copyright 2018 The Kubernetes Authors.
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/kubernetes/pkg/util/parsers"
)

var minimumSupportedVersion = version.MustParseGeneric("1.29.0")

func ParseBool(str string) (bool, error) {
	switch str {
	case "True", "true":
		return true, nil
	case "False", "false":
		return false, nil
	default:
		return false, fmt.Errorf("could not parse string to bool: the acceptable values for %q are 'True', 'true', 'false' or 'False'", str)
	}
}

// parseSidecarContainerImage supports our Privately Hosted Sidecar Image option
// by iterating the container list and finding a container named "gke-gcsfuse-sidecar"
// If we find "gke-gcsfuse-sidecar":
//   - extract the container image and check if the image is valid
//   - removes the container definition from the container list.
//   - remove any mentions of "gke-gcsfuse-sidecar" from initContainer list.
//   - return image
//
// Note: This methos MUST delete all containers using containerName in the Pod Spec.
func ParseSidecarContainerImage(podSpec *corev1.PodSpec, containerName string) (string, error) {
	var image string

	// Find container named "gke-gcsfuse-sidecar" (sidecarContainerName), extract its image, and remove from list.
	if index, present := containerPresent(podSpec.Containers, containerName); present {
		image = podSpec.Containers[index].Image

		if image != "" {
			copy(podSpec.Containers[index:], podSpec.Containers[index+1:])
			podSpec.Containers = podSpec.Containers[:len(podSpec.Containers)-1]
		}

		if _, _, _, err := parsers.ParseImageName(image); err != nil {
			return "", fmt.Errorf("could not parse input image: %q, error: %w", image, err)
		}
	}

	// Remove any mention of gke-gcsfuse-sidecar from init container list.
	if index, present := containerPresent(podSpec.InitContainers, containerName); present {
		copy(podSpec.InitContainers[index:], podSpec.InitContainers[index+1:])
		podSpec.InitContainers = podSpec.InitContainers[:len(podSpec.InitContainers)-1]
	}

	return image, nil
}
