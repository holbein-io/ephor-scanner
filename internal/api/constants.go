package api

const (
	HeaderContentType     = "Content-Type"
	HeaderContentEncoding = "Content-Encoding"
	HeaderUserAgent       = "User-Agent"

	ContentTypeJSON = "application/json"
	EncodingGzip    = "gzip"

	UserAgentPrefix = "ephor-scanner/"

	PathScanIngest = "/api/v1/scans/ingest"
	PathSBOMIngest = "/api/v1/sbom/ingest"
)
