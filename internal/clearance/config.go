package clearance

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SidecarConfig is the subset of authio.yaml the sidecar reads: local
// providers to wrap. Policy for them lives in Clearance (imported from the
// same file's `clearance:` block by `authio apply`), never here.
//
//	clearance:
//	  providers:
//	    filesystem:
//	      type: stdio
//	      command: npx
//	      args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
//	      env: { LOG_LEVEL: warn }
type SidecarConfig struct {
	Providers []StdioProvider
}

type providerShape struct {
	Type    string            `yaml:"type"`
	Command string            `yaml:"command"`
	Args    []string          `yaml:"args"`
	Env     map[string]string `yaml:"env"`
}

// UnmarshalYAML accepts both the mapping form and the airlock-style scalar
// shorthand (`exec: builtin`), which names a type with no further config.
func (p *providerShape) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		p.Type = n.Value
		return nil
	}
	type plain providerShape
	var v plain
	if err := n.Decode(&v); err != nil {
		return err
	}
	*p = providerShape(v)
	return nil
}

type fileShape struct {
	Clearance struct {
		Providers map[string]providerShape `yaml:"providers"`
	} `yaml:"clearance"`
}

// LoadSidecarConfig reads authio.yaml; a missing file yields an empty
// config (hosted tools + exec only). Unknown keys elsewhere in the file are
// fine — `authio apply` owns the rest of the schema.
func LoadSidecarConfig(path string) (*SidecarConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &SidecarConfig{}, nil
		}
		return nil, err
	}
	var f fileShape
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg := &SidecarConfig{}
	for name, p := range f.Clearance.Providers {
		if !validProviderName(name) {
			return nil, fmt.Errorf("%s: clearance.providers.%s: name must be [a-z0-9_-]", path, name)
		}
		switch p.Type {
		case "stdio":
			if strings.TrimSpace(p.Command) == "" {
				return nil, fmt.Errorf("%s: clearance.providers.%s: command is required", path, name)
			}
			cfg.Providers = append(cfg.Providers, StdioProvider{Name: name, Command: p.Command, Args: p.Args, Env: p.Env})
		case "builtin", "":
			// exec/http builtins are implicit; nothing to spawn.
		default:
			return nil, fmt.Errorf("%s: clearance.providers.%s: type %q is not supported by the sidecar (stdio only)", path, name, p.Type)
		}
	}
	return cfg, nil
}

func validProviderName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
