package mcpintegrity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// corpusEntry is one labelled tool description in testdata/corpus.
type corpusEntry struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	SourceClass string   `json:"source_class"`
	ExpectRules []string `json:"expect_rules"`
	MustDetect  bool     `json:"must_detect"`
	KnownFP     bool     `json:"known_fp"` // benign entry the current rules are known to flag
	Notes       string   `json:"notes"`
}

func loadCorpus(t *testing.T, name string) []corpusEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "corpus", name))
	if err != nil {
		t.Fatal(err)
	}
	var out []corpusEntry
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return out
}

func ruleIDs(hits []ruleHit) []string {
	ids := make([]string, 0, len(hits))
	for _, h := range hits {
		ids = append(ids, h.rule)
	}
	return ids
}

// maxSeverity returns the highest severity in hits, or -1 when empty.
func maxSeverity(hits []ruleHit) Severity {
	m := Severity(-1)
	for _, h := range hits {
		if h.severity > m {
			m = h.severity
		}
	}
	return m
}

// TestCorpus is a living benchmark for the heuristic scanner. A malicious
// entry counts as detected when any finding of severity >= Medium fires.
// Only the benign severity >= High gate (minus entries marked known_fp, unless
// CORPUS_STRICT=1) and the must_detect gate fail the test;
// everything else is reported via t.Logf.
func TestCorpus(t *testing.T) {
	const maxLen = 2000
	mal := loadCorpus(t, "malicious.json")
	ben := loadCorpus(t, "benign.json")

	seen := map[string]bool{}
	for _, e := range append(append([]corpusEntry{}, mal...), ben...) {
		if e.ID == "" || seen[e.ID] {
			t.Fatalf("missing or duplicate corpus id %q", e.ID)
		}
		seen[e.ID] = true
	}

	type tally struct{ total, hit int }
	byClass := map[string]*tally{}
	var missed, mustMissed []string
	hit := 0
	mustTotal, mustHit := 0, 0
	for _, e := range mal {
		hits := scanText(e.Description, maxLen)
		detected := maxSeverity(hits) >= SeverityMedium
		c := byClass[e.SourceClass]
		if c == nil {
			c = &tally{}
			byClass[e.SourceClass] = c
		}
		c.total++
		if detected {
			c.hit++
			hit++
		} else {
			missed = append(missed, e.ID+" ("+e.SourceClass+"): "+e.Notes)
		}
		if e.MustDetect {
			mustTotal++
			if detected {
				mustHit++
			} else {
				mustMissed = append(mustMissed, e.ID)
			}
		}
		// Informational: expected rules that did not fire.
		got := strings.Join(ruleIDs(hits), ",")
		for _, want := range e.ExpectRules {
			if !strings.Contains(got, want) {
				t.Logf("note: %s expected %s but fired [%s]", e.ID, want, got)
			}
		}
	}

	var fpHigh, fpAny []string
	for _, e := range ben {
		hits := scanText(e.Description, maxLen)
		// Oversize (low) alone is not counted as a false positive.
		sev := Severity(-1)
		for _, h := range hits {
			if h.rule != RuleOversizeDescription && h.severity > sev {
				sev = h.severity
			}
		}
		if sev >= SeverityMedium {
			fpAny = append(fpAny, e.ID+" "+strings.Join(ruleIDs(hits), ","))
		}
		if sev >= SeverityHigh {
			fpHigh = append(fpHigh, e.ID+" "+strings.Join(ruleIDs(hits), ","))
		}
	}

	t.Logf("malicious: %d entries, detected (>=medium) %d (%.1f%%)", len(mal), hit, pct(hit, len(mal)))
	classes := make([]string, 0, len(byClass))
	for k := range byClass {
		classes = append(classes, k)
	}
	sort.Strings(classes)
	for _, k := range classes {
		c := byClass[k]
		t.Logf("  %-22s %2d/%2d (%.0f%%)", k, c.hit, c.total, pct(c.hit, c.total))
	}
	t.Logf("must_detect: %d/%d", mustHit, mustTotal)
	t.Logf("benign: %d entries, false positives >=medium: %d (%.1f%%), >=high: %d (%.1f%%)",
		len(ben), len(fpAny), pct(len(fpAny), len(ben)), len(fpHigh), pct(len(fpHigh), len(ben)))
	for _, m := range missed {
		t.Logf("MISSED: %s", m)
	}
	for _, f := range fpAny {
		t.Logf("FALSE POSITIVE: %s", f)
	}

	// Known false positives are logged, not failed, unless CORPUS_STRICT=1.
	strict := os.Getenv("CORPUS_STRICT") == "1"
	known := map[string]bool{}
	for _, e := range ben {
		if e.KnownFP && !strict {
			known[e.ID] = true
		}
	}
	for _, f := range fpHigh {
		id, _, _ := strings.Cut(f, " ")
		if known[id] {
			t.Logf("known false positive (not failing): %s", f)
			continue
		}
		t.Errorf("benign entry flagged at severity >= high: %s", f)
	}
	for _, e := range ben {
		if e.KnownFP && !strings.Contains(strings.Join(fpHigh, "|"), e.ID+" ") && !strings.Contains(strings.Join(fpAny, "|"), e.ID+" ") {
			t.Logf("known_fp entry %s no longer flagged; clear its known_fp flag", e.ID)
		}
	}
	if mustHit < mustTotal {
		t.Errorf("must_detect regression: %d/%d detected; missed %v", mustHit, mustTotal, mustMissed)
	}
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}
