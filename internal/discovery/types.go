package discovery

import (
	"ephor-scanner/config"

	"k8s.io/client-go/kubernetes"
)

type Discoverer struct {
	K8s           kubernetes.Interface
	WorkloadTypes []config.WorkloadTypes
}

func NewDiscoverer(cfg *config.Config, k8s kubernetes.Interface) *Discoverer {
	return &Discoverer{
		K8s:           k8s,
		WorkloadTypes: cfg.ScanWorkloadTypes,
	}
}

type Workload struct {
	Namespace  string
	Name       string
	Kind       string
	Containers []Container
}
type Container struct {
	Name  string
	Image string
}
