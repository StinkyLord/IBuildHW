// Package output provides SBOM serializers.
package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/StinkyLord/cpp-sbom-builder/internal/scanner"
)

func WriteDependencyTree(result *scanner.Result, outputPath string) error {
	if result.DependencyTree == nil || len(result.DependencyTree.Roots) == 0 {
		// Emit an empty array rather than null
		return writeJSON(outputPath, []struct{}{})
	}

	return writeJSON(outputPath, result.DependencyTree.Roots)
}

// writeJSON marshals v as indented JSON and writes it to outputPath (or stdout if "-").
func writeJSON(outputPath string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal dependency tree JSON: %w", err)
	}

	if outputPath == "-" {
		_, err = os.Stdout.Write(data)
		if err == nil {
			_, err = os.Stdout.WriteString("\n")
		}
		return err
	}

	return os.WriteFile(outputPath, append(data, '\n'), 0644)
}
