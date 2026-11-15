package mcpintegrity

import (
	"fmt"
	"regexp"
)

const (
	RuleSecretInArgs    = "MCPI-101"
	RuleSensitiveArg    = "MCPI-102"
	RuleResultInjection = "MCPI-103"
	RuleSecretInResult  = "MCPI-104"
)

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

// secretPatterns match well-known credential formats. They favour precision:
// every pattern has a distinctive prefix or header, so ordinary text does not match.
var secretPatterns = []secretPattern{
	{"AWS access key", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)},
	{"API secret key (sk-)", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{24,}\b`)},
	{"Stripe live key", regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{16,}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"JSON Web Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
}

// scanSecrets reports credential-shaped strings. Evidence names the type and
// shows at most four characters, never the secret.
func scanSecrets(s string, rule string, sev Severity) []ruleHit {
	var hits []ruleHit
	for _, p := range secretPatterns {
		if m := p.re.FindString(s); m != "" {
			hits = append(hits, ruleHit{rule, sev, p.name + " present", redact(m)})
		}
	}
	return hits
}

func redact(secret string) string {
	if len(secret) <= 8 {
		return "****"
	}
	return fmt.Sprintf("%s…(%d chars)", secret[:4], len(secret))
}

// sensitivePathRule reuses the tool-text path rule for call arguments.
var sensitivePathRule = textRules[2]
