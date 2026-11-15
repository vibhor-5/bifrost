package mcpintegrity

import (
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// Capability labels used by the default toxic-flow rules.
const (
	LabelPrivateData      = "private_data"
	LabelUntrustedContent = "untrusted_content"
	LabelExfil            = "exfil"
)

const maxSessions = 10000

var defaultToxicFlows = []ToxicFlow{
	{Name: "private data then exfiltration", From: LabelPrivateData, To: LabelExfil},
	{Name: "untrusted content then exfiltration", From: LabelUntrustedContent, To: LabelExfil},
}

type session struct {
	labels map[string]string // label -> first tool that carried it
	seen   time.Time
}

// sessionTracker remembers which capability labels each session has touched.
// Entries expire after ttl and the map is bounded by maxSessions.
type sessionTracker struct {
	mu       sync.Mutex
	ttl      time.Duration
	sessions map[string]*session
}

func newSessionTracker(ttl time.Duration) *sessionTracker {
	return &sessionTracker{ttl: ttl, sessions: map[string]*session{}}
}

// check returns the flow a call to a tool carrying labels would complete, if
// any, and otherwise records the labels against the session.
func (t *sessionTracker) check(id, tool string, labels []string, flows []ToxicFlow, now time.Time) (*ToxicFlow, string) {
	if len(labels) == 0 {
		return nil, ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(now)
	s := t.sessions[id]
	if s == nil {
		if len(t.sessions) >= maxSessions {
			return nil, ""
		}
		s = &session{labels: map[string]string{}}
		t.sessions[id] = s
	}
	s.seen = now
	for i := range flows {
		f := &flows[i]
		if !hasLabel(labels, f.To) {
			continue
		}
		if via, ok := s.labels[f.From]; ok {
			return f, via
		}
	}
	for _, l := range labels {
		if _, ok := s.labels[l]; !ok {
			s.labels[l] = tool
		}
	}
	return nil, ""
}

func (t *sessionTracker) sweepLocked(now time.Time) {
	if len(t.sessions) < 256 {
		return
	}
	for id, s := range t.sessions {
		if now.Sub(s.seen) > t.ttl {
			delete(t.sessions, id)
		}
	}
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// labelsFor resolves a tool's labels: explicit config first (exact name, then
// the longest "prefix*" match), then annotation inference if enabled.
func (p *Plugin) labelsFor(tool string) []string {
	if l, ok := p.cfg.ToolLabels[tool]; ok {
		return l
	}
	best, bestLen := []string(nil), -1
	for pat, l := range p.cfg.ToolLabels {
		if prefix, ok := strings.CutSuffix(pat, "*"); ok && strings.HasPrefix(tool, prefix) && len(prefix) > bestLen {
			best, bestLen = l, len(prefix)
		}
	}
	if bestLen >= 0 {
		return best
	}
	if p.cfg.InferLabels {
		p.mu.RLock()
		l := p.inferred[tool]
		p.mu.RUnlock()
		return l
	}
	return nil
}

// inferLabels derives labels from MCP annotations. openWorldHint means the tool
// talks to external entities, so it can ingest untrusted content; if it is also
// not read-only it can send data out.
func inferLabels(tool schemas.ChatTool) []string {
	a := tool.Annotations
	if a == nil || a.OpenWorldHint == nil || !*a.OpenWorldHint {
		return nil
	}
	labels := []string{LabelUntrustedContent}
	if a.ReadOnlyHint == nil || !*a.ReadOnlyHint {
		labels = append(labels, LabelExfil)
	}
	return labels
}

// sessionID picks the most specific caller identity on the context.
func sessionID(ctx *schemas.BifrostContext) string {
	for _, k := range []schemas.BifrostContextKey{
		schemas.BifrostContextKeyGovernanceVirtualKeyID,
		schemas.BifrostContextKeyMCPSessionID,
		schemas.BifrostContextKeySessionID,
	} {
		if v, _ := ctx.Value(k).(string); v != "" {
			return v
		}
	}
	return "default"
}
