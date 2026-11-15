package mcpintegrity

import "fmt"

// Mode controls what the plugin does when it detects a problem.
type Mode string

const (
	// ModeMonitor records findings but never alters tool lists or blocks calls.
	ModeMonitor Mode = "monitor"
	// ModeEnforce quarantines offending tools: they are removed from the tool
	// list the LLM sees and any direct call to them is refused.
	ModeEnforce Mode = "enforce"
)

// Severity ranks a finding. Higher is worse.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// ParseSeverity converts a config string into a Severity.
func ParseSeverity(v string) (Severity, error) {
	for s, n := range severityNames {
		if n == v {
			return s, nil
		}
	}
	return SeverityInfo, fmt.Errorf("mcpintegrity: unknown severity %q", v)
}

// NewToolPolicy decides what happens to a tool that appears after a server's
// tool set has already been pinned.
type NewToolPolicy string

const (
	NewToolAllow      NewToolPolicy = "allow"
	NewToolQuarantine NewToolPolicy = "quarantine"
)

// Config is the plugin configuration (the `config` object in config.json).
type Config struct {
	// Mode is "monitor" (default) or "enforce".
	Mode Mode `json:"mode,omitempty"`

	// StateFile, when set, persists pins to disk so they survive restarts.
	// Without it, pins live in memory and the first tool list after a restart
	// is trusted again.
	StateFile string `json:"state_file,omitempty"`

	// BlockSeverity is the lowest scanner severity that quarantines a tool in
	// enforce mode ("low", "medium", "high", "critical"). Default "high".
	BlockSeverity string `json:"block_severity,omitempty"`

	// OnNewTool applies to tools that show up after the first pin of a server.
	// Default "allow" (a finding is still recorded).
	OnNewTool NewToolPolicy `json:"on_new_tool,omitempty"`

	// Servers limits the plugin to the named MCP clients. Empty means all.
	Servers []string `json:"servers,omitempty"`

	// DisableScanner turns off description scanning and keeps only pinning.
	DisableScanner bool `json:"disable_scanner,omitempty"`

	// MaxDescriptionLength flags descriptions longer than this many bytes.
	// Default 2000; 0 keeps the default, negative disables the check.
	MaxDescriptionLength int `json:"max_description_length,omitempty"`

	// MaxFindings bounds the in-memory findings buffer. Default 1000.
	MaxFindings int `json:"max_findings,omitempty"`

	// FindingsLog appends every finding as one JSON line to this file.
	FindingsLog string `json:"findings_log,omitempty"`

	// ScanArguments inspects tool-call arguments for secrets and sensitive paths.
	ScanArguments bool `json:"scan_arguments,omitempty"`

	// ScanResults inspects tool results for injected instructions and secrets.
	ScanResults bool `json:"scan_results,omitempty"`

	// MaxCallsPerMinute flags (and in enforce mode refuses) calls to one tool
	// above this rate. 0 disables.
	MaxCallsPerMinute int `json:"max_calls_per_minute,omitempty"`

	// ArgSizeAnomalyFactor flags a call whose arguments are this many times
	// larger than the tool's running average. 0 disables.
	ArgSizeAnomalyFactor float64 `json:"arg_size_anomaly_factor,omitempty"`

	// ToolLabels assigns capability labels ("private_data", "untrusted_content",
	// "exfil", or your own) to tools by exact name or "prefix*".
	ToolLabels map[string][]string `json:"tool_labels,omitempty"`

	// InferLabels derives labels from MCP annotations for unlabelled tools.
	InferLabels bool `json:"infer_labels,omitempty"`

	// ToxicFlows are label sequences to refuse within one session. Defaults to
	// private_data->exfil and untrusted_content->exfil when ToolLabels is set.
	ToxicFlows []ToxicFlow `json:"toxic_flows,omitempty"`

	// SessionTTLSeconds is how long a session's label history is kept. Default 1800.
	SessionTTLSeconds int `json:"session_ttl_seconds,omitempty"`

	// Manifests are signed tool manifests that replace trust-on-first-use.
	Manifests []ManifestRef `json:"manifests,omitempty"`
}

// ToxicFlow forbids calling a tool labelled To once the session has used a tool labelled From.
type ToxicFlow struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

func (c *Config) applyDefaults() (Severity, error) {
	if c.Mode == "" {
		c.Mode = ModeMonitor
	}
	if c.Mode != ModeMonitor && c.Mode != ModeEnforce {
		return 0, fmt.Errorf("mcpintegrity: invalid mode %q", c.Mode)
	}
	if c.OnNewTool == "" {
		c.OnNewTool = NewToolAllow
	}
	if c.OnNewTool != NewToolAllow && c.OnNewTool != NewToolQuarantine {
		return 0, fmt.Errorf("mcpintegrity: invalid on_new_tool %q", c.OnNewTool)
	}
	if c.BlockSeverity == "" {
		c.BlockSeverity = "high"
	}
	sev, err := ParseSeverity(c.BlockSeverity)
	if err != nil {
		return 0, err
	}
	if c.MaxDescriptionLength == 0 {
		c.MaxDescriptionLength = 2000
	}
	if c.MaxFindings <= 0 {
		c.MaxFindings = 1000
	}
	return sev, nil
}
