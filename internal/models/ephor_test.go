package models

import "testing"

func TestSplitImageRef(t *testing.T) {
	tests := []struct {
		ref      string
		wantName string
		wantTag  string
	}{
		{"nginx:1.25", "nginx", "1.25"},
		{"docker.io/library/nginx:latest", "docker.io/library/nginx", "latest"},
		{"nginx@sha256:abc123def", "nginx", "sha256:abc123def"},
		{"nginx", "nginx", "latest"},
		{"registry.io:5000/myapp:v2", "registry.io:5000/myapp", "v2"},
		{"registry.io:5000/myapp", "registry.io:5000/myapp", "latest"},
		{"ghcr.io/org/repo:sha-a1b2c3d", "ghcr.io/org/repo", "sha-a1b2c3d"},
	}

	for _, tt := range tests {
		name, tag := SplitImageRef(tt.ref)
		if name != tt.wantName || tag != tt.wantTag {
			t.Errorf("SplitImageRef(%q) = (%q, %q), want (%q, %q)",
				tt.ref, name, tag, tt.wantName, tt.wantTag)
		}
	}
}
