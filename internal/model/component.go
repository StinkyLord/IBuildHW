// Package model defines the internal data structures used by the SBOM engine.
package model

type Component struct {
	Name            string   // Library name (e.g., "boost", "openssl")
	Version         string   // Detected version string, or "unknown"
	PURL            string   // Package URL (pkg:conan/boost@1.82.0)
	Revision        string   // Conan recipe revision hash (#abc123), if known
	Channel         string   // Conan user/channel (e.g., "conan/stable"), if known
	DetectionSource string   // Which strategy detected this (e.g., "compile_commands.json")
	IncludePaths    []string // External include paths that led to detection
	LinkLibraries   []string // Linked library names (e.g., "boost_system", "ssl")
	Description     string   // Optional description from manifest

	// Dependency hierarchy fields
	IsDirect     bool     // true = directly used by the project; false = transitive
	Dependencies []string // children
}

// Key returns a normalized deduplication key for the component.
// It uses the normalized name (lowercase, _ and . replaced with -)
// combined with the version, so that:
//   - "nlohmann_json@3.11.2" and "nlohmann-json@3.11.2" collapse to the same key
//   - "openssl@1.1.1" and "openssl@3.1.4" remain distinct keys
func (c *Component) Key() string {
	return normalizeKey(c.Name) + "@" + c.Version
}

// normalizeKey returns a normalized map key for a name string:
// lowercase, with underscores and dots replaced by hyphens.
func normalizeKey(name string) string {
	result := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		if b == '_' || b == '.' {
			b = '-'
		}
		result = append(result, b)
	}
	return string(result)
}

// DependencyType returns "direct" or "transitive" for use in SBOM output.
func (c *Component) DependencyType() string {
	if c.IsDirect {
		return "direct"
	}
	return "transitive"
}
