package discovery

import (
	"context"
	"ephor-scanner/config"
	"log/slog"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func (d *Discoverer) Discover(ctx context.Context, namespaces []string) ([]Workload, error) {

	var workloads []Workload

	for _, ns := range namespaces {
		for _, wt := range d.WorkloadTypes {
			discovered, err := discoverByType(ctx, d.K8s, wt, ns)
			if err != nil {
				slog.Error("discovery failed", "namespace", ns, "type", wt, "error", err)
				continue
			}
			workloads = append(workloads, discovered...)
		}
	}

	return workloads, nil
}

func discoverByType(ctx context.Context, k kubernetes.Interface, wt config.WorkloadTypes, ns string) ([]Workload, error) {
	switch wt {
	case config.Deployment:
		return discoverDeployments(ctx, k, ns)
	case config.StatefulSet:
		return discoverStatefulSet(ctx, k, ns)
	case config.DaemonSet:
		return discoverDaemonSets(ctx, k, ns)
	case config.CronJob:
		return discoverCronJobs(ctx, k, ns)
	default:
		return nil, nil
	}
}

func discoverCronJobs(ctx context.Context, k kubernetes.Interface, ns string) ([]Workload, error) {
	list, err := k.BatchV1().CronJobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var workloads []Workload
	for _, cj := range list.Items {
		containers := extractContainers(cj.Spec.JobTemplate.Spec.Template.Spec)
		workloads = append(workloads, Workload{
			Namespace:  cj.Namespace,
			Name:       cj.Name,
			Kind:       config.CronJob.String(),
			Containers: containers,
		})
	}
	return workloads, nil
}

func discoverDaemonSets(ctx context.Context, k kubernetes.Interface, ns string) ([]Workload, error) {
	list, err := k.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var workloads []Workload
	for _, ds := range list.Items {
		containers := extractContainers(ds.Spec.Template.Spec)
		workloads = append(workloads, Workload{
			Namespace:  ds.Namespace,
			Name:       ds.Name,
			Kind:       config.DaemonSet.String(),
			Containers: containers,
		})
	}
	return workloads, nil
}

func discoverStatefulSet(ctx context.Context, k kubernetes.Interface, ns string) ([]Workload, error) {
	list, err := k.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var workloads []Workload
	for _, ss := range list.Items {
		containers := extractContainers(ss.Spec.Template.Spec)
		workloads = append(workloads, Workload{
			Namespace:  ss.Namespace,
			Name:       ss.Name,
			Kind:       config.StatefulSet.String(),
			Containers: containers,
		})
	}
	return workloads, nil
}

func discoverDeployments(ctx context.Context, k kubernetes.Interface, ns string) ([]Workload, error) {
	list, err := k.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var workloads []Workload
	for _, depl := range list.Items {
		containers := extractContainers(depl.Spec.Template.Spec)
		workloads = append(workloads, Workload{
			Namespace:  depl.Namespace,
			Name:       depl.Name,
			Kind:       config.Deployment.String(),
			Containers: containers,
		})
	}
	return workloads, nil
}

func extractContainers(podSpec corev1.PodSpec) []Container {
	var containers []Container
	for _, c := range podSpec.InitContainers {
		containers = append(containers, Container{Name: c.Name, Image: normalizeImageRef(c.Image)})
	}
	for _, c := range podSpec.Containers {
		containers = append(containers, Container{Name: c.Name, Image: normalizeImageRef(c.Image)})
	}
	return containers
}

func normalizeImageRef(image string) string {
	// Strip tag/digest to isolate the name portion
	name := image
	if i := strings.LastIndex(name, "@"); i != -1 {
		name = name[:i]
	}
	if i := strings.LastIndex(name, ":"); i != -1 {
		name = name[:i]
	}

	// If the first segment contains a dot or colon, it's already a registry hostname
	firstSegment := name
	if i := strings.Index(name, "/"); i != -1 {
		firstSegment = name[:i]
	}
	if strings.ContainsAny(firstSegment, ".:") {
		return image
	}

	// Docker Hub: single segment = official image, otherwise user image
	if !strings.Contains(name, "/") {
		return "docker.io/library/" + image
	}
	return "docker.io/" + image
}
