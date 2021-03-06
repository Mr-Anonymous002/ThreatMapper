package xfer

const (
	// AppPort is the default port that the app will use for its HTTP server.
	// The app publishes the API and user interface, and receives reports from
	// probes, on this port.
	AppPort = 8004

	// ScopeProbeIDHeader is the header we use to carry the probe's unique ID. The
	// ID is currently set to the a random string on probe startup.
	ScopeProbeIDHeader = "X-Deepfence-Discovery-Id"

	// ScopeProbeVersionHeader is the header we use to carry the probe's version.
	ScopeProbeVersionHeader = "X-deepfence-discovery-Version"
)

// HistoricReportsCapability indicates whether reports older than the
// current time (-app.window) can be retrieved.
const HistoricReportsCapability = "historic_reports"

// Details are some generic details that can be fetched from /api
type Details struct {
	ID           string          `json:"id"`
	Version      string          `json:"version"`
	Hostname     string          `json:"hostname"`
	Plugins      PluginSpecs     `json:"plugins,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`

	NewVersion *NewVersionInfo `json:"newVersion,omitempty"`
}

// NewVersionInfo is the struct exposed in /api when there is a new
// version of Scope available.
type NewVersionInfo struct {
	Version     string `json:"version"`
	DownloadURL string `json:"downloadUrl"`
}
