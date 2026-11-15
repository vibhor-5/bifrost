package mcpintegrity

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Rule IDs are stable so operators can reference them in alerts and tests.
const (
	RuleInstructionOverride = "MCPI-001"
	RuleConcealment         = "MCPI-002"
	RuleSensitivePath       = "MCPI-003"
	RuleImportantTag        = "MCPI-004"
	RuleInvisibleUnicode    = "MCPI-005"
	RuleEncodedBlob         = "MCPI-006"
	RuleOversizeDescription = "MCPI-007"
	RuleToolShadowing       = "MCPI-008"
	RuleExfilURL            = "MCPI-009"
	RuleDependencyHijack    = "MCPI-010"
)

type textRule struct {
	id       string
	severity Severity
	title    string
	re       *regexp.Regexp
}

// textRules are heuristics for the instruction-injection patterns documented in
// public MCP tool-poisoning research. They are deliberately conservative: a
// match is a reason to look, and the pin check, not these rules, is what
// detects a change.
var textRules = []textRule{
	{RuleInstructionOverride, SeverityHigh, "instruction override in tool text",
		regexp.MustCompile(`(?i)(\b(ignore|disregard|forget|override|supersede)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|system)\b[^.\n]{0,40}\b(instructions?|rules?|prompts?|guidelines?)\b|\bpay no attention to\b[^.\n]{0,40}\b(told|instructed|before|earlier)\b|\bfrom now on,? you (must|will|should|shall) (follow|obey|only)\b|\bignor(e|a|ez|iere)\b[^.\n]{0,30}(instruc|anweisung|consignes|指令|инструкци))`)},
	{RuleConcealment, SeverityHigh, "tool text asks to hide actions from the user",
		regexp.MustCompile(`(?i)(\b(do not|don't|never|without)\b[^.\n]{0,30}\b(tell(ing)?|inform(ing)?|notif(y|ying)|mention(ing)?|reveal(ing)?|alert(ing)?|show(ing)?)\b[^.\n]{0,30}\buser\b[^.\n]{0,25}\b((about|that)\b|of (this|these|it|that|the (call|action|step|request|instruction|task))\b)|\b(keep|hide|conceal)\b[^.\n]{0,30}\b(this|these|it)\b[^.\n]{0,30}\bfrom (the )?user\b|\bthe user\b[^.\n]{0,20}\b(must not|should not|can't|cannot|never) (see|know|find out|learn|notice)\b|\b(silently|secretly|covertly)\b[^.\n]{0,40}\b(send|forward|upload|copy|read|include|attach|call)\b|(no (le|lo) (digas|diga|dis)|nicht sagen|ne (le )?dites pas|不要告诉|не говори)[^.\n]{0,30})`)},
	{RuleSensitivePath, SeverityMedium, "tool text references credentials or config files",
		regexp.MustCompile(`(?i)(~/\.ssh|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.env\b|mcp\.json|\.npmrc|\.netrc|/etc/passwd|/etc/shadow|\.kube/config)`)},
	{RuleImportantTag, SeverityMedium, "pseudo-system tag embedded in tool text",
		regexp.MustCompile(`(?i)(<\s*/?\s*(important|system|instructions?|secret|admin|override)\s*>|\[\s*(important|system|override|admin)\s*\]|#{2,}\s*(system|important|override)\b)`)},
	{RuleEncodedBlob, SeverityMedium, "long encoded blob in tool text",
		regexp.MustCompile(`[A-Za-z0-9+/]{60,}={0,2}`)},
	{RuleExfilURL, SeverityMedium, "tool text embeds a URL together with a send/post instruction",
		regexp.MustCompile(`(?is)\b(send|post|upload|forward|exfiltrate|transmit|append|embed|include|encode|put)\b[^\n]{0,80}https?://`)},
	{RuleDependencyHijack, SeverityMedium, "tool text redirects the model to call another tool first",
		regexp.MustCompile(`(?i)(\b(before|prior to) (using|calling|running|invoking) (this|the) tool\b[^.\n]{0,60}\b(call|invoke|run|use)\b|\balways (call|invoke|run) \w+ first\b)`)},
}

// sensitiveVerb marks a verb that turns a file mention into an instruction to
// touch the file. A path on its own is documentation; a path after "read",
// "send" or "include" is a request.
var sensitiveVerb = regexp.MustCompile(`(?i)\b(read|cat|open|include|send|upload|pass|attach|load|fetch|copy|append|print|output|dump|exfiltrate|forward|share)\b[^.\n]{0,60}$`)

// scanText runs the text rules and the Unicode and size checks over s.
// Findings carry the rule ID and a short, sanitised evidence excerpt; the full
// text is never copied into a finding because it is attacker controlled.
func scanText(s string, maxLen int) []ruleHit {
	var hits []ruleHit
	// Match against the text with invisible characters removed as well, so a
	// word split by zero-width characters ("ig\u200bnore") cannot slip past.
	stripped := stripInvisible(s)
	for _, r := range textRules {
		loc := r.re.FindStringIndex(s)
		text := s
		if loc == nil && stripped != s {
			if loc = r.re.FindStringIndex(stripped); loc != nil {
				text = stripped
			}
		}
		if loc == nil {
			continue
		}
		sev := r.severity
		if r.id == RuleSensitivePath && sensitiveVerb.MatchString(text[:loc[0]]) {
			sev = SeverityHigh
		}
		hits = append(hits, ruleHit{r.id, sev, r.title, excerpt(text, loc[0], loc[1])})
	}
	strong, weak := countInvisible(s)
	if strong > 0 {
		hits = append(hits, ruleHit{RuleInvisibleUnicode, SeverityHigh,
			"hidden or bidirectional-override Unicode characters in tool text",
			fmt.Sprintf("%d hidden code points", strong)})
	} else if weak > 0 {
		hits = append(hits, ruleHit{RuleInvisibleUnicode, SeverityLow,
			"joiner or directional-mark characters in tool text",
			fmt.Sprintf("%d code points", weak)})
	}
	if maxLen > 0 && len(s) > maxLen {
		hits = append(hits, ruleHit{RuleOversizeDescription, SeverityLow,
			"unusually long tool description", fmt.Sprintf("%d bytes (limit %d)", len(s), maxLen)})
	}
	return hits
}

type ruleHit struct {
	rule     string
	severity Severity
	title    string
	evidence string
}

// countInvisible counts characters that render as nothing to a human reviewer
// but are read by the model. "Strong" ones have no everyday use in a tool
// description: Unicode tag characters, bidi overrides and isolates, zero-width
// space, word joiner and BOM. "Weak" ones (ZWJ, ZWNJ, LRM, RLM and other format
// characters) are routine in emoji sequences and Arabic or Indic text.
func countInvisible(s string) (strong, weak int) {
	for _, r := range s {
		switch {
		case r >= 0xE0000 && r <= 0xE007F,
			r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069,
			r == 0x200B, r == 0x2060, r == 0xFEFF:
			strong++
		case unicode.Is(unicode.Cf, r) && r != 0x00AD:
			weak++
		}
	}
	return strong, weak
}

// stripInvisible removes every format-class character.
func stripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// shadowedTools returns the names of other servers' tools that desc mentions.
// A description that talks about a different tool is the signature of a
// "tool shadowing" attack: it tries to change how the model uses that tool.
// known maps bare tool name -> owning client; own is the describing client.
func shadowedTools(desc, own string, known map[string]string) []string {
	if desc == "" {
		return nil
	}
	lower := strings.ToLower(desc)
	var out []string
	for name, owner := range known {
		if owner == own || len(name) < 5 {
			continue
		}
		if containsWord(lower, strings.ToLower(name)) {
			out = append(out, name)
		}
	}
	return out
}

func containsWord(haystack, word string) bool {
	for i := 0; ; {
		j := strings.Index(haystack[i:], word)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(word)
		beforeOK := start == 0 || !isWordChar(rune(haystack[start-1]))
		afterOK := end == len(haystack) || !isWordChar(rune(haystack[end]))
		if beforeOK && afterOK {
			return true
		}
		i = start + 1
	}
}

func isWordChar(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// excerpt returns a bounded, control-character-free window around a match.
func excerpt(s string, start, end int) string {
	const pad, max = 20, 120
	lo := start - pad
	if lo < 0 {
		lo = 0
	}
	hi := end + pad
	if hi > len(s) {
		hi = len(s)
	}
	if hi-lo > max {
		hi = lo + max
	}
	out := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s[lo:hi])
	return strings.TrimSpace(out)
}
