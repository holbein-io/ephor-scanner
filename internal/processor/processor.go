package processor

import (
	"ephor-scanner/internal/discovery"
	"ephor-scanner/internal/models"
	"ephor-scanner/internal/scanner"
	"log/slog"
	"time"
)

func BuildNamespacePayload(namespace string, workloads []discovery.Workload, scanResults map[string]*ScanResult, meta ScanMeta) *models.ScanIngestRequest {
	var failedImages, totalImages int
	var workloadPayloads []models.WorkloadData

	for _, w := range workloads {
		var containers []models.ContainerData

		for _, c := range w.Containers {
			totalImages++
			imageName, imageTag := models.SplitImageRef(c.Image)

			cd := models.ContainerData{
				Name:      c.Name,
				ImageName: imageName,
				ImageTag:  imageTag,
			}

			result, ok := scanResults[c.Image]
			if !ok || result.Err != nil {
				failedImages++
				if ok && result.Err != nil {
					slog.Error("scan failed for image",
						"namespace", namespace,
						"workload", w.Name,
						"container", c.Name,
						"image", c.Image,
						"error", result.Err,
					)
				} else {
					slog.Error("no scan result for image",
						"namespace", namespace,
						"workload", w.Name,
						"container", c.Name,
						"image", c.Image,
					)
				}
				containers = append(containers, cd)
				continue
			}

			cd.Vulnerabilities = mapVulnerabilities(result.Report)
			cd.DetectedEcosystems = extractEcosystems(result.Report)
			if result.Report.Metadata.OS != nil {
				cd.OSFamily = result.Report.Metadata.OS.Family
				cd.OSName = result.Report.Metadata.OS.Name
			}
			cd.RepoDigests = result.Report.Metadata.RepoDigests
			containers = append(containers, cd)
		}

		workloadPayloads = append(workloadPayloads, models.WorkloadData{
			Namespace:  w.Namespace,
			Name:       w.Name,
			Kind:       w.Kind,
			Containers: containers,
			Labels:     w.Labels,
		})
	}

	now := time.Now()
	status := determineStatus(totalImages, failedImages)

	return &models.ScanIngestRequest{
		Namespace:    namespace,
		ScanLabel:    meta.ScanLabel,
		ScanGroupId:  meta.ScanGroupID,
		Status:       status,
		StartedAt:    &meta.StartedAt,
		CompletedAt:  &now,
		TrivyVersion: meta.TrivyVersion,
		Workloads:    workloadPayloads,
	}
}

func mapVulnerabilities(report *scanner.TrivyReport) []models.VulnerabilityData {
	var vulns []models.VulnerabilityData
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			vd := models.VulnerabilityData{
				CveId:          v.VulnerabilityID,
				PackageName:    v.PkgName,
				PackageVersion: v.InstalledVersion,
				PackageClass:   result.Class,
				PackageType:    result.Type,
				Severity:       v.Severity,
				Title:          v.Title,
				Description:    v.Description,
				PrimaryURL:     v.PrimaryURL,
				FixedVersion:   v.FixedVersion,
				ScannerType:    result.Type,
				References:     v.References,
			}

			if v.PublishedDate != "" {
				if t, err := time.Parse(time.RFC3339, v.PublishedDate); err == nil {
					vd.PublishedDate = &t
				}
			}

			vd.CvssV3Vector, vd.CvssV3Score = extractCVSSv3(v.CVSS)

			vulns = append(vulns, vd)
		}
	}
	return vulns
}

func extractCVSSv3(cvss map[string]scanner.TrivyCVSS) (string, float64) {
	// Prefer NVD source, fall back to first available
	if nvd, ok := cvss["nvd"]; ok && nvd.V3Vector != "" {
		return nvd.V3Vector, nvd.V3Score
	}
	for _, c := range cvss {
		if c.V3Vector != "" {
			return c.V3Vector, c.V3Score
		}
	}
	return "", 0
}

func extractEcosystems(report *scanner.TrivyReport) []string {
	seen := make(map[string]bool)
	var ecosystems []string
	for _, result := range report.Results {
		if result.Type != "" && !seen[result.Type] {
			seen[result.Type] = true
			ecosystems = append(ecosystems, result.Type)
		}
	}
	return ecosystems
}

func determineStatus(total, failed int) models.ScanStatus {
	if total == 0 || failed == total {
		return models.ScanStatusFailed
	}
	return models.ScanStatusCompleted
}
