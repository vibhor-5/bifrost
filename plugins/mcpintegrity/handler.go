package mcpintegrity

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Handler returns an http.Handler exposing the plugin's state:
//
//	GET  /findings?min_severity=high&limit=50
//	GET  /quarantine
//	GET  /pins
//	POST /approve?client=<c>&tool=<t>
//	GET  /metrics            (Prometheus text format)
//
// It performs no authentication. Mount it behind the gateway's admin auth or
// on a private listener; /approve changes what the model is allowed to call.
func (p *Plugin) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /findings", p.serveFindings)
	mux.HandleFunc("GET /quarantine", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"quarantined": p.Quarantined()})
	})
	mux.HandleFunc("GET /pins", p.servePins)
	mux.HandleFunc("POST /approve", p.serveApprove)
	mux.HandleFunc("GET /metrics", p.serveMetrics)
	return mux
}

func (p *Plugin) serveFindings(w http.ResponseWriter, r *http.Request) {
	minSev := SeverityInfo
	if v := r.URL.Query().Get("min_severity"); v != "" {
		s, err := ParseSeverity(v)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		minSev = s
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
			return
		}
		limit = n
	}
	all := p.Findings()
	out := make([]Finding, 0, min(limit, len(all)))
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- { // newest first
		if all[i].Severity >= minSev {
			out = append(out, all[i])
		}
	}
	writeJSON(w, map[string]any{"findings": out})
}

func (p *Plugin) servePins(w http.ResponseWriter, _ *http.Request) {
	type pin struct {
		Hash      string `json:"hash"`
		FirstSeen string `json:"first_seen"`
	}
	out := map[string]map[string]pin{}
	p.store.mu.Lock()
	for client, sp := range p.store.servers {
		m := map[string]pin{}
		for name, tp := range sp.Tools {
			m[name] = pin{Hash: tp.Hash, FirstSeen: tp.FirstSeen.Format("2006-01-02T15:04:05Z07:00")}
		}
		out[client] = m
	}
	p.store.mu.Unlock()
	writeJSON(w, map[string]any{"pins": out})
}

func (p *Plugin) serveApprove(w http.ResponseWriter, r *http.Request) {
	client, tool := r.URL.Query().Get("client"), r.URL.Query().Get("tool")
	if client == "" || tool == "" {
		http.Error(w, "client and tool query parameters are required", http.StatusBadRequest)
		return
	}
	p.Approve(client, tool)
	writeJSON(w, map[string]any{"approved": client + "/" + tool})
}

func (p *Plugin) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	p.WriteMetrics(w)
}

// WriteMetrics writes Prometheus text-format counters for findings by kind and
// severity, plus the number of currently quarantined tools.
func (p *Plugin) WriteMetrics(w io.Writer) {
	p.mu.RLock()
	keys := make([]string, 0, len(p.counts))
	for k := range p.counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintln(w, "# HELP bifrost_mcp_integrity_findings_total Findings raised by the mcp-integrity plugin.")
	fmt.Fprintln(w, "# TYPE bifrost_mcp_integrity_findings_total counter")
	for _, k := range keys {
		kind, sev, _ := strings.Cut(k, "|")
		fmt.Fprintf(w, "bifrost_mcp_integrity_findings_total{kind=%q,severity=%q} %d\n", kind, sev, p.counts[k])
	}
	quarantined := 0
	for _, tools := range p.quarantined {
		quarantined += len(tools)
	}
	p.mu.RUnlock()
	fmt.Fprintln(w, "# HELP bifrost_mcp_integrity_quarantined_tools Tools currently quarantined.")
	fmt.Fprintln(w, "# TYPE bifrost_mcp_integrity_quarantined_tools gauge")
	fmt.Fprintf(w, "bifrost_mcp_integrity_quarantined_tools %d\n", quarantined)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
