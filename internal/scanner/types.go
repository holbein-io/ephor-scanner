package scanner

// TrivyReport is the top-level JSON output from `trivy image --format json`.
// We only unmarshal the fields we need; the rest (Metadata, ImageConfig, etc.) is ignored.
type TrivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Results       []TrivyResult `json:"Results"`
}

type TrivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"` // "os-pkgs", "lang-pkgs"
	Type            string               `json:"Type"`  // "debian", "alpine", "gomod", "npm", etc.
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

// TODO: useful information to include later on
// Metadata.OS, Metadata.ImageID/RepoDigests
// ImageConfig.history --> ???
// Vulnerability.CVSS
// Vulnerability.References
// Vulnerability.Layer
type TrivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion,omitempty"`
	Status           string `json:"Status"` // "affected", "fixed", etc.
	Severity         string `json:"Severity"`
	Title            string `json:"Title,omitempty"`
	Description      string `json:"Description,omitempty"`
	PrimaryURL       string `json:"PrimaryURL,omitempty"`
	PublishedDate    string `json:"PublishedDate,omitempty"`
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
