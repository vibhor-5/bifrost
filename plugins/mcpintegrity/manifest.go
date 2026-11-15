package mcpintegrity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Manifest is the set of tool fingerprints a server owner (or an operator who
// vetted the server) vouches for. Signing it replaces trust on first use with
// an explicit root of trust: the first tool list is checked, not assumed good.
type Manifest struct {
	Server   string            `json:"server"`
	Tools    map[string]string `json:"tools"` // client-prefixed tool name -> fingerprint
	IssuedAt time.Time         `json:"issued_at"`
}

// SignedManifest is a Manifest with an Ed25519 signature over its canonical JSON.
type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"` // base64
}

// ManifestRef points the plugin at a signed manifest file and its trusted key.
type ManifestRef struct {
	Server    string `json:"server"`
	Path      string `json:"path"`
	PublicKey string `json:"public_key"` // base64 Ed25519 public key
}

func canonicalManifest(m Manifest) ([]byte, error) {
	// encoding/json sorts map keys, so this encoding is deterministic.
	return json.Marshal(m)
}

// SignManifest signs m with priv.
func SignManifest(priv ed25519.PrivateKey, m Manifest) (SignedManifest, error) {
	msg, err := canonicalManifest(m)
	if err != nil {
		return SignedManifest{}, err
	}
	return SignedManifest{Manifest: m, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))}, nil
}

// Verify checks the signature against pub.
func (s SignedManifest) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key length")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return fmt.Errorf("signature is not base64: %w", err)
	}
	msg, err := canonicalManifest(s.Manifest)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("signature does not match manifest")
	}
	return nil
}

// LoadManifest reads, verifies and returns the manifest a ref points at.
func LoadManifest(ref ManifestRef) (*Manifest, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(ref.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("manifest %q: public_key is not base64: %w", ref.Server, err)
	}
	data, err := os.ReadFile(ref.Path)
	if err != nil {
		return nil, fmt.Errorf("manifest %q: %w", ref.Server, err)
	}
	var sm SignedManifest
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, fmt.Errorf("manifest %q: %w", ref.Server, err)
	}
	if err := sm.Verify(ed25519.PublicKey(pubBytes)); err != nil {
		return nil, fmt.Errorf("manifest %q: %w", ref.Server, err)
	}
	if sm.Manifest.Server != ref.Server {
		return nil, fmt.Errorf("manifest %q: signed for server %q", ref.Server, sm.Manifest.Server)
	}
	return &sm.Manifest, nil
}

// ManifestFromStateFile builds an unsigned manifest from the pins a gateway
// recorded for server. Review it, then sign it with SignManifest.
func ManifestFromStateFile(path, server string) (Manifest, error) {
	st, err := newPinStore(path)
	if err != nil {
		return Manifest{}, err
	}
	sp := st.servers[server]
	if sp == nil || len(sp.Tools) == 0 {
		return Manifest{}, fmt.Errorf("no pinned tools for server %q in %s", server, path)
	}
	m := Manifest{Server: server, Tools: map[string]string{}, IssuedAt: time.Now().UTC()}
	for name, pin := range sp.Tools {
		m.Tools[name] = pin.Hash
	}
	return m, nil
}
