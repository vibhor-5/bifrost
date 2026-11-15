package mcpintegrity

import (
	"fmt"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

const (
	ctxKeyTool schemas.BifrostContextKey = "mcp-integrity-tool"

	// maxScanBytes bounds how much of an argument or result is scanned, so a
	// huge payload cannot turn a security check into a latency problem.
	maxScanBytes = 256 << 10

	notice = "[content withheld by mcp-integrity: tool output contained injected instructions]"
)

// resultRules are the text rules that mean something in tool output. File
// paths, base64 and odd Unicode are routine in results (directory listings,
// binary data), so only instruction-shaped text is reported there.
var resultRules = map[string]bool{
	RuleInstructionOverride: true,
	RuleConcealment:         true,
	RuleImportantTag:        true,
	RuleExfilURL:            true,
}

// guardCall runs the call-time checks in order and returns a short-circuit when
// enforce mode refuses the call. Every check is behind a flag, so a plugin
// configured for pinning only does no extra work per call.
func (p *Plugin) guardCall(ctx *schemas.BifrostContext, req *schemas.BifrostMCPRequest, tool string) *schemas.MCPPluginShortCircuit {
	enforce := p.cfg.Mode == ModeEnforce
	client := req.ClientName

	if enforce {
		if reason, blocked := p.isQuarantined(client, tool); blocked {
			return p.deny(Finding{Kind: KindBlockedCall, Severity: SeverityHigh, Client: client, Tool: tool,
				Message: "call to quarantined tool refused: " + reason, Quarantined: true}, "quarantined: "+reason)
		}
	}

	var args string
	if p.cfg.ScanArguments || p.behavior != nil {
		if a, ok := req.GetToolArguments().(string); ok {
			args = a
		}
	}

	if p.cfg.ScanArguments && args != "" {
		scan := args
		if len(scan) > maxScanBytes {
			scan = scan[:maxScanBytes]
		}
		hits := scanSecrets(scan, RuleSecretInArgs, SeverityHigh)
		if loc := sensitivePathRule.re.FindStringIndex(scan); loc != nil {
			hits = append(hits, ruleHit{RuleSensitiveArg, SeverityMedium, "arguments reference a credential or config file", excerpt(scan, loc[0], loc[1])})
		}
		for _, h := range hits {
			f := Finding{Kind: KindSecretInArgs, Severity: h.severity, Rule: h.rule, Client: client, Tool: tool,
				Message: h.title, Evidence: h.evidence}
			if enforce && h.severity >= p.blockSev {
				return p.deny(f, h.title)
			}
			p.record(f)
		}
	}

	if p.behavior != nil {
		v := p.behavior.observe(client+"\x00"+tool, len(args), time.Now(), p.cfg.MaxCallsPerMinute, p.cfg.ArgSizeAnomalyFactor)
		if v.rateExceeded {
			f := Finding{Kind: KindRateAnomaly, Severity: SeverityHigh, Client: client, Tool: tool,
				Message: fmt.Sprintf("%d calls in the last minute exceeds limit %d", v.count, p.cfg.MaxCallsPerMinute)}
			if enforce {
				return p.deny(f, "call rate limit exceeded")
			}
			p.record(f)
		}
		if v.oversize {
			f := Finding{Kind: KindArgSizeAnomaly, Severity: SeverityMedium, Client: client, Tool: tool,
				Message: fmt.Sprintf("arguments are %d bytes, far above the tool's usual %.0f", len(args), v.avg)}
			if enforce && SeverityMedium >= p.blockSev {
				return p.deny(f, "argument size anomaly")
			}
			p.record(f)
		}
	}

	if p.sessions != nil {
		if labels := p.labelsFor(tool); len(labels) > 0 {
			if flow, via := p.sessions.check(sessionID(ctx), tool, labels, p.flows, time.Now()); flow != nil {
				f := Finding{Kind: KindToxicFlow, Severity: SeverityCritical, Client: client, Tool: tool,
					Message: fmt.Sprintf("%s: %q follows %q in the same session", flow.Name, tool, via)}
				if enforce {
					return p.deny(f, flow.Name)
				}
				p.record(f)
			}
		}
	}
	return nil
}

// deny records a blocked finding and builds the 403 short-circuit.
func (p *Plugin) deny(f Finding, reason string) *schemas.MCPPluginShortCircuit {
	f.Blocked = true
	p.record(f)
	return &schemas.MCPPluginShortCircuit{Error: &schemas.BifrostError{
		StatusCode: schemas.Ptr(403),
		Error: &schemas.ErrorField{
			Message: fmt.Sprintf("tool call refused by %s: %s", PluginName, reason),
		},
	}}
}

// checkResult scans a tool result for injected instructions and credentials.
// In enforce mode a result containing a blocking-severity injection is replaced
// by a neutral notice so the model never reads it.
func (p *Plugin) checkResult(ctx *schemas.BifrostContext, resp *schemas.BifrostMCPResponse) {
	client, _ := ctx.Value(ctxKeyClient).(string)
	tool, _ := ctx.Value(ctxKeyTool).(string)
	if client == "" || !p.watches(client) {
		return
	}
	texts := resultTexts(resp)
	block := false
	for _, t := range texts {
		scan := *t
		if len(scan) > maxScanBytes {
			scan = scan[:maxScanBytes]
		}
		for _, h := range scanText(scan, 0) {
			if !resultRules[h.rule] {
				continue
			}
			p.record(Finding{Kind: KindResultInjection, Severity: h.severity, Rule: h.rule, Client: client, Tool: tool,
				Message: "tool result: " + h.title, Evidence: h.evidence, Blocked: p.cfg.Mode == ModeEnforce && h.severity >= p.blockSev})
			if h.severity >= p.blockSev {
				block = true
			}
		}
		for _, h := range scanSecrets(scan, RuleSecretInResult, SeverityMedium) {
			p.record(Finding{Kind: KindSecretInResult, Severity: h.severity, Rule: h.rule, Client: client, Tool: tool,
				Message: "tool result: " + h.title, Evidence: h.evidence})
		}
	}
	if block && p.cfg.Mode == ModeEnforce {
		for _, t := range texts {
			*t = notice
		}
	}
}

// resultTexts returns pointers to every text field of a tool result so they
// can be both scanned and rewritten in place.
func resultTexts(resp *schemas.BifrostMCPResponse) []*string {
	var out []*string
	if m := resp.ChatMessage; m != nil && m.Content != nil {
		if m.Content.ContentStr != nil {
			out = append(out, m.Content.ContentStr)
		}
		for i := range m.Content.ContentBlocks {
			if t := m.Content.ContentBlocks[i].Text; t != nil {
				out = append(out, t)
			}
		}
	}
	if r := resp.ResponsesMessage; r != nil && r.ResponsesToolMessage != nil && r.ResponsesToolMessage.Output != nil {
		if s := r.ResponsesToolMessage.Output.ResponsesToolCallOutputStr; s != nil {
			out = append(out, s)
		}
	}
	return out
}
