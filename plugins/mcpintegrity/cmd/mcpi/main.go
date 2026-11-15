// Command mcpi manages signed MCP tool manifests for the mcp-integrity plugin.
//
//	mcpi keygen  -out key            writes key.pub and key.priv (base64)
//	mcpi sign    -state pins.json -server NAME -key key.priv -out manifest.json
//	mcpi verify  -manifest manifest.json -pub key.pub
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/maximhq/bifrost/plugins/mcpintegrity"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpi:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mcpi keygen|sign|verify [flags]")
	os.Exit(2)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "mcpi-key", "output path prefix")
	fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out+".pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(*out+".priv", []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s.pub and %s.priv\n", *out, *out)
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	state := fs.String("state", "", "plugin state_file with the pinned tools")
	server := fs.String("server", "", "MCP client name to build the manifest for")
	keyPath := fs.String("key", "", "private key file from keygen")
	out := fs.String("out", "manifest.json", "output manifest path")
	fs.Parse(args)
	if *state == "" || *server == "" || *keyPath == "" {
		return fmt.Errorf("-state, -server and -key are required")
	}
	m, err := mcpintegrity.ManifestFromStateFile(*state, *server)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("%s is not a valid private key", *keyPath)
	}
	sm, err := mcpintegrity.SignManifest(ed25519.PrivateKey(priv), m)
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(sm, "", "  ")
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %d tools for %q -> %s\n", len(m.Tools), *server, *out)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	path := fs.String("manifest", "", "signed manifest")
	pubPath := fs.String("pub", "", "public key file")
	fs.Parse(args)
	raw, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	server := ""
	if data, err := os.ReadFile(*path); err == nil {
		var sm mcpintegrity.SignedManifest
		if json.Unmarshal(data, &sm) == nil {
			server = sm.Manifest.Server
		}
	}
	m, err := mcpintegrity.LoadManifest(mcpintegrity.ManifestRef{
		Server: server, Path: *path, PublicKey: strings.TrimSpace(string(raw)),
	})
	if err != nil {
		return err
	}
	fmt.Printf("ok: manifest for %q lists %d tools\n", m.Server, len(m.Tools))
	return nil
}
