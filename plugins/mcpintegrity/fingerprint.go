package mcpintegrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/maximhq/bifrost/core/schemas"
)

// toolFingerprint hashes everything an LLM (or the gateway) could act on in a
// tool definition: name, description, input schema, annotations and MCP
// metadata. Any change to those fields changes the hash, which is what makes a
// post-approval "rug pull" detectable.
//
// Only fields that reach the model or drive gateway behaviour are hashed;
// cache-control and Anthropic-specific flags are Bifrost-side and ignored.
func toolFingerprint(name string, tool schemas.ChatTool) string {
	view := struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		Function    any    `json:"function,omitempty"`
		Custom      any    `json:"custom,omitempty"`
		Annotations any    `json:"annotations,omitempty"`
		MCP         any    `json:"mcp,omitempty"`
	}{
		Name:        name,
		Type:        string(tool.Type),
		Function:    tool.Function,
		Custom:      tool.Custom,
		Annotations: tool.Annotations,
		MCP:         tool.MCP,
	}
	return hashJSON(view)
}

// instructionsFingerprint hashes the server-supplied usage instructions.
func instructionsFingerprint(instructions string) string {
	sum := sha256.Sum256([]byte(instructions))
	return hex.EncodeToString(sum[:])
}

func hashJSON(v any) string {
	// encoding/json sorts map keys, so the encoding is stable for a given value.
	b, err := json.Marshal(v)
	if err != nil {
		// A tool we cannot serialise gets a hash that can never match a pin,
		// so it is treated as changed rather than silently trusted.
		return "unhashable"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// toolDescription returns the model-visible description of a tool.
func toolDescription(tool schemas.ChatTool) string {
	if tool.Function != nil && tool.Function.Description != nil {
		return *tool.Function.Description
	}
	return ""
}
