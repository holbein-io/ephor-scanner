package discovery

import (
	"context"
	"fmt"
	"testing"

	"ephor-scanner/config"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestDiscover_MultipleWorkloadTypes(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "nginx", Image: "nginx:1.25"},
						},
					},
				},
			},
		},
		&batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Name: "cleanup", Namespace: "jobs"},
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{Name: "cleaner", Image: "busybox:latest"},
								},
							},
						},
					},
				},
			},
		},
	)

	d := &Discoverer{
		K8s:           client,
		WorkloadTypes: []config.WorkloadTypes{config.Deployment, config.CronJob},
	}

	workloads, err := d.Discover(context.Background(), []string{"prod", "jobs"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(workloads) != 2 {
		t.Fatalf("expected 2 workloads, got %d", len(workloads))
	}

	found := map[string]Workload{}
	for _, w := range workloads {
		found[w.Name] = w
	}

	web, ok := found["web"]
	if !ok {
		t.Fatal("expected workload 'web' not found")
	}
	if web.Kind != "Deployment" || web.Namespace != "prod" {
		t.Errorf("web: got kind=%s ns=%s, want kind=Deployment ns=prod", web.Kind, web.Namespace)
	}
	if len(web.Containers) != 1 || web.Containers[0].Image != "docker.io/library/nginx:1.25" {
		t.Errorf("web: unexpected containers %v", web.Containers)
	}

	cleanup, ok := found["cleanup"]
	if !ok {
		t.Fatal("expected workload 'cleanup' not found")
	}
	if cleanup.Kind != "CronJob" || cleanup.Namespace != "jobs" {
		t.Errorf("cleanup: got kind=%s ns=%s, want kind=CronJob ns=jobs", cleanup.Kind, cleanup.Namespace)
	}
}

func TestDiscover_EmptyNamespace(t *testing.T) {
	client := fake.NewSimpleClientset()

	d := &Discoverer{
		K8s:           client,
		WorkloadTypes: []config.WorkloadTypes{config.Deployment, config.StatefulSet, config.DaemonSet, config.CronJob},
	}

	workloads, err := d.Discover(context.Background(), []string{"empty-ns"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(workloads) != 0 {
		t.Errorf("expected 0 workloads, got %d", len(workloads))
	}
}

func TestDiscover_InitContainers(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "prod"},
			Spec: appsv1.StatefulSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{Name: "init-schema", Image: "migrate:v2"},
						},
						Containers: []corev1.Container{
							{Name: "postgres", Image: "postgres:16"},
						},
					},
				},
			},
		},
	)

	d := &Discoverer{
		K8s:           client,
		WorkloadTypes: []config.WorkloadTypes{config.StatefulSet},
	}

	workloads, err := d.Discover(context.Background(), []string{"prod"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(workloads) != 1 {
		t.Fatalf("expected 1 workload, got %d", len(workloads))
	}

	containers := workloads[0].Containers
	if len(containers) != 2 {
		t.Fatalf("expected 2 containers (init + regular), got %d", len(containers))
	}

	if containers[0].Name != "init-schema" || containers[0].Image != "docker.io/library/migrate:v2" {
		t.Errorf("init container: got %v, want name=init-schema image=docker.io/library/migrate:v2", containers[0])
	}
	if containers[1].Name != "postgres" || containers[1].Image != "docker.io/library/postgres:16" {
		t.Errorf("regular container: got %v, want name=postgres image=docker.io/library/postgres:16", containers[1])
	}
}

func TestDiscover_ErrorContinues(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "healthy"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "myapp:v1"},
						},
					},
				},
			},
		},
	)

	// Inject an error for the "broken" namespace
	client.PrependReactor("list", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetNamespace() == "broken" {
			return true, nil, fmt.Errorf("forbidden: namespace broken")
		}
		return false, nil, nil
	})

	d := &Discoverer{
		K8s:           client,
		WorkloadTypes: []config.WorkloadTypes{config.Deployment},
	}

	workloads, err := d.Discover(context.Background(), []string{"broken", "healthy"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(workloads) != 1 {
		t.Fatalf("expected 1 workload (skipping broken ns), got %d", len(workloads))
	}

	if workloads[0].Name != "api" || workloads[0].Namespace != "healthy" {
		t.Errorf("expected workload api/healthy, got %s/%s", workloads[0].Name, workloads[0].Namespace)
	}
}
