package mcpintegrity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// serverPin is the trusted baseline for one MCP client.
type serverPin struct {
	// Tools maps client-prefixed tool name -> fingerprint.
	Tools map[string]toolPin `json:"tools"`
	// InstructionsHash pins the server's initialize-time instructions.
	InstructionsHash string `json:"instructions_hash,omitempty"`
	// Initialised is true once a full tool list has been pinned. Tools seen
	// after that point count as "new" rather than as part of the baseline.
	Initialised bool `json:"initialised"`
	// Approved lists tools an operator approved that will be pinned, as
	// reviewed, the next time they are listed.
	Approved map[string]bool `json:"approved,omitempty"`
	PinnedAt time.Time       `json:"pinned_at"`
}

type toolPin struct {
	Hash      string    `json:"hash"`
	FirstSeen time.Time `json:"first_seen"`
	// Reviewed marks a pin an operator approved; the scanner no longer
	// quarantines that exact definition.
	Reviewed bool `json:"reviewed,omitempty"`
}

type pinFile struct {
	Version int                   `json:"version"`
	Servers map[string]*serverPin `json:"servers"`
}

// pinStore holds pins in memory and optionally mirrors them to a JSON file.
type pinStore struct {
	mu      sync.Mutex
	path    string
	servers map[string]*serverPin
}

func newPinStore(path string) (*pinStore, error) {
	s := &pinStore{path: path, servers: map[string]*serverPin{}}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mcpintegrity: read state file: %w", err)
	}
	var pf pinFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("mcpintegrity: parse state file %s: %w", path, err)
	}
	if pf.Servers != nil {
		s.servers = pf.Servers
	}
	return s, nil
}

// server returns the pin for a client, creating it if absent. Caller holds mu.
func (s *pinStore) server(client string) *serverPin {
	sp := s.servers[client]
	if sp == nil {
		sp = &serverPin{Tools: map[string]toolPin{}}
		s.servers[client] = sp
	}
	if sp.Tools == nil {
		sp.Tools = map[string]toolPin{}
	}
	return sp
}

// saveLocked writes the store atomically (temp file + rename) so a crash never
// leaves a truncated baseline that would silently reset trust. Caller holds mu.
func (s *pinStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(pinFile{Version: 1, Servers: s.servers}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".mcpintegrity-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
