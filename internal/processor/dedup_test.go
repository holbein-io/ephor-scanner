package processor

import (
	"ephor-scanner/internal/discovery"
	"sort"
	"testing"
)

func TestDeduplicateImages_CrossNamespace(t *testing.T) {
	workloads := []discovery.Workload{
		{
			Namespace: "prod",
			Name:      "web",
			Kind:      "Deployment",
			Containers: []discovery.Container{
				{Name: "nginx", Image: "nginx:1.25"},
				{Name: "sidecar", Image: "envoy:v1.30"},
			},
		},
		{
			Namespace: "staging",
			Name:      "web",
			Kind:      "Deployment",
			Containers: []discovery.Container{
				{Name: "nginx", Image: "nginx:1.25"},
			},
		},
		{
			Namespace: "prod",
			Name:      "api",
			Kind:      "Deployment",
			Containers: []discovery.Container{
				{Name: "app", Image: "myapp:v2"},
			},
		},
	}

	result := DeduplicateImages(workloads)
	sort.Strings(result)

	expected := []string{"envoy:v1.30", "myapp:v2", "nginx:1.25"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d unique images, got %d: %v", len(expected), len(result), result)
	}
	for i, img := range expected {
		if result[i] != img {
			t.Errorf("result[%d] = %q, want %q", i, result[i], img)
		}
	}
}
