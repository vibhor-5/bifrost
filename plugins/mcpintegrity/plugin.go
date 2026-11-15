// Package mcpintegrity is a Bifrost MCP plugin that pins MCP tool definitions
// and detects tampering ("rug pulls"), tool poisoning and tool shadowing.
//
// On the first tool list from a server it records a SHA-256 fingerprint of each
// tool (trust on first use). Later lists are compared to that baseline; a tool
// whose name, description, schema or annotations changed is reported and, in
// enforce mode, quarantined: removed from the tool list the model sees and
// refused at call time. Tool text is also scanned for hidden-instruction
// patterns, invisible Unicode, and references to other servers' tools.
package mcpintegrity

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

const (
	// PluginName is the identifier used in config.json.
	PluginName = "mcp-integrity"

	ctxKeyClient schemas.BifrostContextKey = "mcp-integrity-client"
)

// Kind classifies a finding.
type Kind string

const (
	KindToolChanged         Kind = "tool_changed"
	KindToolAdded           Kind = "tool_added"
	KindToolRemoved         Kind = "tool_removed"
	KindPoisoning           Kind = "poisoning_pattern"
	KindShadowing           Kind = "tool_shadowing"
	KindInstructionsChanged Kind = "instructions_changed"
	KindBlockedCall         Kind = "blocked_call"
	KindToolUnlisted        Kind = "tool_not_in_manifest"
	KindSecretInArgs        Kind = "secret_in_arguments"
	KindSecretInResult      Kind = "secret_in_result"
	KindResultInjection     Kind = "result_injection"
	KindRateAnomaly         Kind = "call_rate_anomaly"
	KindArgSizeAnomaly      Kind = "argument_size_anomaly"
	KindToxicFlow           Kind = "toxic_flow"
)

// Finding is one security observation. It never contains full tool text,
// which is attacker-controlled; Evidence is a short sanitised excerpt.
type Finding struct {
	Time        time.Time `json:"time"`
	Kind        Kind      `json:"kind"`
	Severity    Severity  `json:"-"`
	SeverityStr string    `json:"severity"`
	Rule        string    `json:"rule,omitempty"`
	Client      string    `json:"client"`
	Tool        string    `json:"tool,omitempty"`
	Message     string    `json:"message"`
	Evidence    string    `json:"evidence,omitempty"`
	Quarantined bool      `json:"quarantined"`
	Blocked     bool      `json:"blocked,omitempty"`
}

// Plugin implements schemas.MCPPlugin and schemas.MCPConnectionPlugin.
type Plugin struct {
	cfg       Config
	blockSev  Severity
	logger    schemas.Logger
	store     *pinStore
	servers   map[string]struct{}
	onFinding func(Finding)

	behavior  *behaviorTracker // nil unless rate or size checks are configured
	sessions  *sessionTracker  // nil unless toxic-flow checks are active
	flows     []ToxicFlow
	manifests map[string]*Manifest
	logFile   *os.File
	logMu     sync.Mutex

	mu          sync.RWMutex
	quarantined map[string]map[string]string // client -> tool -> reason
	findings    []Finding
	toolOwners  map[string]string   // tool name -> client, for shadowing checks
	inferred    map[string][]string // tool -> labels derived from annotations
	counts      map[string]uint64   // "kind|severity" -> findings raised
}

var (
	_ schemas.MCPPlugin           = (*Plugin)(nil)
	_ schemas.MCPConnectionPlugin = (*Plugin)(nil)
)

// Init builds the plugin. logger may be nil.
func Init(cfg Config, logger schemas.Logger) (*Plugin, error) {
	sev, err := cfg.applyDefaults()
	if err != nil {
		return nil, err
	}
	store, err := newPinStore(cfg.StateFile)
	if err != nil {
		return nil, err
	}
	p := &Plugin{
		cfg:         cfg,
		blockSev:    sev,
		logger:      logger,
		store:       store,
		servers:     map[string]struct{}{},
		quarantined: map[string]map[string]string{},
		toolOwners:  map[string]string{},
		inferred:    map[string][]string{},
		counts:      map[string]uint64{},
		manifests:   map[string]*Manifest{},
	}
	for _, s := range cfg.Servers {
		p.servers[s] = struct{}{}
	}
	for _, ref := range cfg.Manifests {
		m, err := LoadManifest(ref)
		if err != nil {
			return nil, fmt.Errorf("mcpintegrity: %w", err)
		}
		p.manifests[ref.Server] = m
	}
	if cfg.MaxCallsPerMinute > 0 || cfg.ArgSizeAnomalyFactor > 0 {
		p.behavior = newBehaviorTracker()
	}
	if len(cfg.ToolLabels) > 0 || cfg.InferLabels {
		p.flows = cfg.ToxicFlows
		if len(p.flows) == 0 {
			p.flows = defaultToxicFlows
		}
		ttl := time.Duration(cfg.SessionTTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 30 * time.Minute
		}
		p.sessions = newSessionTracker(ttl)
	}
	if cfg.FindingsLog != "" {
		f, err := os.OpenFile(cfg.FindingsLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("mcpintegrity: open findings log: %w", err)
		}
		p.logFile = f
	}
	return p, nil
}

// OnFinding registers a callback invoked synchronously for every finding.
// Use it to forward findings to alerting; it must not block.
func (p *Plugin) OnFinding(fn func(Finding)) { p.onFinding = fn }

func (p *Plugin) GetName() string { return PluginName }

func (p *Plugin) Cleanup() error {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	if p.logFile != nil {
		err := p.logFile.Close()
		p.logFile = nil
		return err
	}
	return nil
}

func (p *Plugin) watches(client string) bool {
	if len(p.servers) == 0 {
		return true
	}
	_, ok := p.servers[client]
	return ok
}

// PreMCPHook runs the call-time guards (quarantine, arguments, rate, toxic
// flow) and remembers the client and tool for the post hook, which has no
// request to read them from.
func (p *Plugin) PreMCPHook(ctx *schemas.BifrostContext, req *schemas.BifrostMCPRequest) (*schemas.BifrostMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	if req == nil {
		return req, nil, nil
	}
	if req.RequestType == schemas.MCPRequestTypeListTools {
		ctx.SetValue(ctxKeyClient, req.ClientName)
		return req, nil, nil
	}
	if !req.RequestType.IsExecuteTool() {
		return req, nil, nil
	}
	tool := req.GetToolName()
	ctx.SetValue(ctxKeyClient, req.ClientName)
	ctx.SetValue(ctxKeyTool, tool)
	if !p.watches(req.ClientName) {
		return req, nil, nil
	}
	if sc := p.guardCall(ctx, req, tool); sc != nil {
		return req, sc, nil
	}
	return req, nil, nil
}

// PostMCPHook inspects list_tools results and, if enabled, tool call results.
func (p *Plugin) PostMCPHook(ctx *schemas.BifrostContext, resp *schemas.BifrostMCPResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostMCPResponse, *schemas.BifrostError, error) {
	if bifrostErr != nil || resp == nil {
		return resp, bifrostErr, nil
	}
	if resp.BifrostMCPListToolsResponse == nil {
		if p.cfg.ScanResults {
			p.checkResult(ctx, resp)
		}
		return resp, bifrostErr, nil
	}
	client := resp.ExtraFields.ClientName
	if client == "" {
		client, _ = ctx.Value(ctxKeyClient).(string)
	}
	if client == "" || !p.watches(client) {
		return resp, bifrostErr, nil
	}
	p.inspectTools(client, resp.Tools)
	if p.cfg.Mode == ModeEnforce {
		// Hide quarantined tools from the model, not just from execution.
		p.mu.RLock()
		for name := range p.quarantined[client] {
			delete(resp.Tools, name)
		}
		p.mu.RUnlock()
	}
	return resp, bifrostErr, nil
}

// PreMCPConnectionHook is a no-op; integrity checks run on the handshake result.
func (p *Plugin) PreMCPConnectionHook(_ *schemas.BifrostContext, req *schemas.BifrostMCPConnectRequest) (*schemas.BifrostMCPConnectRequest, *schemas.MCPConnectionShortCircuit, error) {
	return req, nil, nil
}

// PostMCPConnectionHook pins and scans the server's initialize instructions,
// which are injected into the model's context just like tool descriptions.
func (p *Plugin) PostMCPConnectionHook(_ *schemas.BifrostContext, resp *schemas.BifrostMCPConnectResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostMCPConnectResponse, *schemas.BifrostError, error) {
	if bifrostErr != nil || resp == nil {
		return resp, bifrostErr, nil
	}
	client := resp.ExtraFields.ClientName
	if client == "" || !p.watches(client) {
		return resp, bifrostErr, nil
	}
	p.inspectInstructions(client, resp.Instructions)
	return resp, bifrostErr, nil
}

func (p *Plugin) inspectInstructions(client, instructions string) {
	hash := instructionsFingerprint(instructions)

	p.store.mu.Lock()
	sp := p.store.server(client)
	prev := sp.InstructionsHash
	changed := prev != "" && prev != hash
	if prev == "" || changed && p.cfg.Mode == ModeMonitor {
		// Monitor mode follows the server; enforce mode keeps the old pin so
		// the change keeps being reported until an operator approves it.
		sp.InstructionsHash = hash
		p.persistLocked()
	}
	p.store.mu.Unlock()

	if changed {
		p.record(Finding{Kind: KindInstructionsChanged, Severity: SeverityHigh, Client: client,
			Message: "server instructions changed since they were pinned"})
	}
	if p.cfg.DisableScanner {
		return
	}
	for _, h := range scanText(instructions, 0) {
		p.record(Finding{Kind: KindPoisoning, Severity: h.severity, Rule: h.rule, Client: client,
			Message: "server instructions: " + h.title, Evidence: h.evidence})
	}
}

// inspectTools compares a fresh tool list with the baseline and scans it.
// In enforce mode it updates the quarantine set for the client.
func (p *Plugin) inspectTools(client string, tools map[string]schemas.ChatTool) {
	now := time.Now()
	names := make([]string, 0, len(tools))
	for n := range tools {
		names = append(names, n)
	}
	sort.Strings(names)

	next := map[string]string{}   // tool -> quarantine reason
	reviewed := map[string]bool{} // tools whose current definition an operator approved
	var findings []Finding

	p.store.mu.Lock()
	sp := p.store.server(client)
	manifest := p.manifests[client]
	if manifest != nil {
		// A signed manifest is the baseline: nothing is learned from the server.
		sp.Tools = map[string]toolPin{}
		for n, h := range manifest.Tools {
			sp.Tools[n] = toolPin{Hash: h, FirstSeen: manifest.IssuedAt}
		}
		sp.Initialised = true
	}
	initial := !sp.Initialised

	for _, name := range names {
		tool := tools[name]
		hash := toolFingerprint(name, tool)
		pin, known := sp.Tools[name]
		switch {
		case sp.Approved[name] && manifest == nil:
			sp.Tools[name] = toolPin{Hash: hash, FirstSeen: now, Reviewed: true}
			delete(sp.Approved, name)
			reviewed[name] = true
		case known && pin.Reviewed && pin.Hash == hash:
			reviewed[name] = true
		case !known && manifest != nil:
			findings = append(findings, Finding{Kind: KindToolUnlisted, Severity: SeverityCritical, Client: client, Tool: name,
				Message: "tool is not in the signed manifest"})
			next[name] = "not in signed manifest"
		case !known && initial:
			sp.Tools[name] = toolPin{Hash: hash, FirstSeen: now}
		case !known:
			findings = append(findings, Finding{Kind: KindToolAdded, Severity: SeverityLow, Client: client, Tool: name,
				Message: "tool appeared after the server's tools were pinned"})
			if p.cfg.OnNewTool == NewToolQuarantine {
				next[name] = "new tool not yet approved"
			} else {
				sp.Tools[name] = toolPin{Hash: hash, FirstSeen: now}
			}
		case pin.Hash != hash:
			msg, reason := "tool definition changed after it was pinned (possible rug pull)", "definition changed since pin"
			if manifest != nil {
				msg, reason = "tool definition does not match the signed manifest", "does not match signed manifest"
			}
			findings = append(findings, Finding{Kind: KindToolChanged, Severity: SeverityCritical, Client: client, Tool: name,
				Message: msg})
			next[name] = reason
		}
	}
	for name := range sp.Tools {
		if _, still := tools[name]; !still {
			findings = append(findings, Finding{Kind: KindToolRemoved, Severity: SeverityInfo, Client: client, Tool: name,
				Message: "pinned tool is no longer offered"})
		}
	}
	if initial {
		sp.Initialised = true
		sp.PinnedAt = now
	}
	if manifest == nil {
		p.persistLocked()
	}
	p.store.mu.Unlock()

	if p.cfg.InferLabels {
		p.mu.Lock()
		for _, name := range names {
			if l := inferLabels(tools[name]); l != nil {
				p.inferred[name] = l
			}
		}
		p.mu.Unlock()
	}

	if !p.cfg.DisableScanner {
		p.mu.Lock()
		for _, name := range names {
			p.toolOwners[name] = client
		}
		known := make(map[string]string, len(p.toolOwners))
		for n, c := range p.toolOwners {
			known[n] = c
		}
		p.mu.Unlock()

		for _, name := range names {
			desc := toolDescription(tools[name])
			for _, h := range scanText(desc, p.cfg.MaxDescriptionLength) {
				findings = append(findings, Finding{Kind: KindPoisoning, Severity: h.severity, Rule: h.rule,
					Client: client, Tool: name, Message: h.title, Evidence: h.evidence})
				if h.severity >= p.blockSev && !reviewed[name] {
					if _, already := next[name]; !already {
						next[name] = h.rule + ": " + h.title
					}
				}
			}
			for _, victim := range shadowedTools(desc, client, bareNames(known)) {
				findings = append(findings, Finding{Kind: KindShadowing, Severity: SeverityMedium, Rule: RuleToolShadowing,
					Client: client, Tool: name, Message: "description mentions another server's tool " + victim})
				if SeverityMedium >= p.blockSev && !reviewed[name] {
					if _, already := next[name]; !already {
						next[name] = RuleToolShadowing + ": references tool " + victim
					}
				}
			}
		}
	}

	if p.cfg.Mode == ModeEnforce {
		p.mu.Lock()
		if len(next) == 0 {
			delete(p.quarantined, client)
		} else {
			p.quarantined[client] = next
		}
		p.mu.Unlock()
	}

	for _, f := range findings {
		_, f.Quarantined = next[f.Tool]
		f.Quarantined = f.Quarantined && p.cfg.Mode == ModeEnforce
		p.record(f)
	}
}

// bareNames adapts the owner map (prefixed tool name -> client) into the shape
// shadowedTools expects, keyed by the tool name without its "client-" prefix.
func bareNames(owners map[string]string) map[string]string {
	out := make(map[string]string, len(owners))
	for full, client := range owners {
		bare := full
		if len(full) > len(client)+1 && full[:len(client)+1] == client+"-" {
			bare = full[len(client)+1:]
		}
		out[bare] = client
	}
	return out
}

func (p *Plugin) isQuarantined(client, tool string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	reason, ok := p.quarantined[client][tool]
	return reason, ok
}

// Approve lifts a tool's quarantine and marks its next-listed definition as
// reviewed: it is pinned as the new baseline and the scanner stops quarantining
// that exact definition. Until the server next lists its tools the tool stays
// hidden; call the gateway's tool refresh to apply it immediately.
func (p *Plugin) Approve(client, tool string) {
	p.store.mu.Lock()
	sp := p.store.server(client)
	if sp.Approved == nil {
		sp.Approved = map[string]bool{}
	}
	sp.Approved[tool] = true
	p.persistLocked()
	p.store.mu.Unlock()

	p.mu.Lock()
	delete(p.quarantined[client], tool)
	p.mu.Unlock()
}

// Quarantined lists "client/tool: reason" entries, sorted.
func (p *Plugin) Quarantined() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var out []string
	for c, tools := range p.quarantined {
		for t, r := range tools {
			out = append(out, c+"/"+t+": "+r)
		}
	}
	slices.Sort(out)
	return out
}

// Findings returns a copy of the buffered findings, oldest first.
func (p *Plugin) Findings() []Finding {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return slices.Clone(p.findings)
}

func (p *Plugin) record(f Finding) {
	f.Time = time.Now()
	f.SeverityStr = f.Severity.String()

	p.mu.Lock()
	if len(p.findings) >= p.cfg.MaxFindings {
		p.findings = append(p.findings[:0], p.findings[1:]...)
	}
	p.findings = append(p.findings, f)
	p.counts[string(f.Kind)+"|"+f.SeverityStr]++
	p.mu.Unlock()

	p.appendLog(f)

	if p.logger != nil {
		msg := fmt.Sprintf("[%s] %s %s client=%s tool=%s: %s", PluginName, f.SeverityStr, f.Kind, f.Client, f.Tool, f.Message)
		if f.Severity >= SeverityHigh {
			p.logger.Warn(msg)
		} else {
			p.logger.Info(msg)
		}
	}
	if p.onFinding != nil {
		p.onFinding(f)
	}
}

func (p *Plugin) persistLocked() {
	if err := p.store.saveLocked(); err != nil && p.logger != nil {
		p.logger.Warn(fmt.Sprintf("[%s] failed to persist pins: %v", PluginName, err))
	}
}

// appendLog writes one JSON line per finding to the configured findings log.
// Findings never contain full tool text or secrets, so the file is safe to ship
// to a SIEM or to keep as a research dataset.
func (p *Plugin) appendLog(f Finding) {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	if p.logFile == nil {
		return
	}
	line, err := json.Marshal(f)
	if err != nil {
		return
	}
	if _, err := p.logFile.Write(append(line, '\n')); err != nil && p.logger != nil {
		p.logger.Warn(fmt.Sprintf("[%s] failed to write findings log: %v", PluginName, err))
	}
}
