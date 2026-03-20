package scanner

// TrivyReport is the top-level JSON output from `trivy image --format json`.
type TrivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Metadata      TrivyMetadata `json:"Metadata"`
	Results       []TrivyResult `json:"Results"`
}

type TrivyMetadata struct {
	OS          *TrivyOS `json:"OS,omitempty"`
	RepoDigests []string `json:"RepoDigests,omitempty"`
}

type TrivyOS struct {
	Family string `json:"Family"` // "debian", "alpine", "redhat", etc.
	Name   string `json:"Name"`   // "12.8", "3.21", etc.
}

type TrivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"` // "os-pkgs", "lang-pkgs"
	Type            string               `json:"Type"`  // "debian", "alpine", "gomod", "npm", etc.
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	PkgName          string               `json:"PkgName"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion,omitempty"`
	Status           string               `json:"Status"`
	Severity         string               `json:"Severity"`
	Title            string               `json:"Title,omitempty"`
	Description      string               `json:"Description,omitempty"`
	PrimaryURL       string               `json:"PrimaryURL,omitempty"`
	PublishedDate    string               `json:"PublishedDate,omitempty"`
	References       []string             `json:"References,omitempty"`
	CVSS             map[string]TrivyCVSS `json:"CVSS,omitempty"`
}

type TrivyCVSS struct {
	V3Vector string  `json:"V3Vector,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
	V2Vector string  `json:"V2Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
}

type TrivyVersion struct {
	Version         string       `json:"Version"`
	VulnerabilityDB DBDetails    `json:"VulnerabilityDB"`
	JavaDB          DBDetails    `json:"JavaDB"`
	CheckBundle     BundleDetail `json:"CheckBundle"`
}

type DBDetails struct {
	Version      int    `json:"Version"`
	NextUpdate   string `json:"NextUpdate"`
	UpdatedAt    string `json:"UpdatedAt"`
	DownloadedAt string `json:"DownloadedAt"`
}

type BundleDetail struct {
	Digest       string `json:"Digest"`
	DownloadedAt string `json:"DownloadedAt"`
}
