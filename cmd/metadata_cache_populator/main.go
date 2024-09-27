/*
Copyright 2018 The Kubernetes Authors.
Copyright 2024 Google LLC

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

package main

import (
	"context"
	"flag"
	"os"
	"os/exec"

	"k8s.io/klog/v2"
)

var (
// This is set at compile time.
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	ctx := context.Background()

	command := "ls"
	args := []string{"-R", "/volumes"}
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout = os.Stdout

}
