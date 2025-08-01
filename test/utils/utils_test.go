/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"testing"
)

func TestIsKindCluster(t *testing.T) {
	// This test just ensures the function runs without error
	// The actual result will depend on the environment where the test runs
	isKind := IsKindCluster()
	t.Logf("Current context is a Kind cluster: %v", isKind)
}
