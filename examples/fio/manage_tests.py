#!/usr/bin/env python

# Copyright 2018 The Kubernetes Authors.
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import subprocess
import sys
import yaml


def run_command(command: str):
    result = subprocess.run(command.split(" "), capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr)

valid_volume_attributes = {
    "skipCSIBucketAccessCheck",
    "gcsfuseMetadataPrefetchOnMount",
    "gcsfuseLoggingSeverity",
    "disableMetrics",
}

data=None
with open('gke-fio-config.yaml', 'r') as file:
    try:
        data = yaml.safe_load(file)
        # Process the 'data' (it's now a Python dictionary or list)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")


# Load all storage layouts
storage_layouts = []
for layout in data['storageLayouts']:
    bucketName = layout['bucketName']
    fileSize = layout['fileSize']
    blockSize = layout['blockSize']
    storage_layouts.append((bucketName, fileSize, blockSize))

# Load all test scenarios
scenarios = []
for scenario in data['scenarios']:
    opts="\\,".join(scenario['mountOptions'])
    scenarios.append((scenario['name'], scenario['volumeAttributes'], opts))


# Apply all combinations to helm chart.
for bucketName, fileSize, blockSize in storage_layouts:    
    for readType in ["randread"]:
        for scenario_name, volume_attributes, mountOptions in scenarios:

            if readType == "randread" and fileSize in ["64K", "128K"]:
                continue

            action = "install"
            if sys.argv[1] == "delete":
                action = "uninstall"

            commands = [f"helm {action} fio-loading-test-{fileSize.lower()}-{readType}-{scenario_name}"]

            if action == "install":
                commands.extend([
                            "loading-test",
                            f"--set bucketName={bucketName}",
                            f"--set scenario={scenario_name}",
                            f"--set fio.readType={readType}",
                            f"--set fio.fileSize={fileSize}",
                            f"--set gcsfuse.mountOptions={mountOptions}"])

                for d in volume_attributes:
                    for attr, val in d.items():
                        if attr in valid_volume_attributes:
                            commands.append(f"--set gcsfuse.volumeAttributes.{attr}={val}")
                        else:
                            raise ValueError(f"{attr} is not a valid volumeAttribute in GCSFuse CSI")

            
                if fileSize == "100M":
                    commands.append("--set fio.filesPerThread=1000")
            helm_command = " ".join(commands)

            # print(helm_command)
            run_command(helm_command)
