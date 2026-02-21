// Package output provides SBOM serializers.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
	"github.com/StinkyLord/cpp-sbom-builder/internal/scanner"
)

// ---- CycloneDX 1.4 JSON schema types ----

type cdxBOM struct {
	BOMFormat      string         `json:"bomFormat"`
	SpecVersion    string         `json:"specVersion"`
	Version        int            `json:"version"`
	SerialNumber   string         `json:"serialNumber"`
	Metadata       cdxMetadata    `json:"metadata"`
	DependencyTree []*cdxTreeNode `json:"dependencyTree,omitempty"`
}

type cdxTreeNode struct {
	Name     string         `json:"name"`
	Version  string         `json:"version"`
	PURL     string         `json:"purl,omitempty"`
	Direct   bool           `json:"direct,omitempty"`
	Children []*cdxTreeNode `json:"children,omitempty"`
}

type cdxMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []cdxTool `json:"tools"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// WriteCycloneDX serialises the scan result as a CycloneDX 1.4 JSON SBOM and
// writes it to the given output path. If outputPath is "-", it writes to stdout.
func WriteCycloneDX(result *scanner.Result, outputPath string, toolVersion string) error {
	bom := buildCycloneDX(result, toolVersion)

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CycloneDX JSON: %w", err)
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

func buildCycloneDX(result *scanner.Result, toolVersion string) cdxBOM {
	// Build the dependencyTree: npm-style tree.
	// Only direct dependencies appear at the root; each carries its full subtree.
	var depTree []*cdxTreeNode
	if result.DependencyTree != nil && len(result.DependencyTree.Roots) > 0 {
		for _, root := range result.DependencyTree.Roots {
			depTree = append(depTree, modelNodeToCDX(root))
		}
	}

	return cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.4",
		Version:      1,
		SerialNumber: generateURN(),
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cdxTool{
				{
					Vendor:  "StinkyLord",
					Name:    "cpp-sbom-builder",
					Version: toolVersion,
				},
			},
		},
		DependencyTree: depTree,
	}
}

// modelNodeToCDX converts a model.TreeNode to a cdxTreeNode iteratively.
func modelNodeToCDX(root *model.TreeNode) *cdxTreeNode {
	type workItem struct {
		src *model.TreeNode
		dst *cdxTreeNode
	}

	rootDst := &cdxTreeNode{
		Name:    root.Name,
		Version: root.Version,
		PURL:    root.PURL,
		Direct:  root.DependencyType == "direct",
	}

	queue := []workItem{{src: root, dst: rootDst}}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		for _, child := range item.src.Children {
			childDst := &cdxTreeNode{
				Name:    child.Name,
				Version: child.Version,
				PURL:    child.PURL,
				Direct:  child.DependencyType == "direct",
			}
			item.dst.Children = append(item.dst.Children, childDst)
			queue = append(queue, workItem{src: child, dst: childDst})
		}
	}

	return rootDst
}

// generateURN produces a simple URN:UUID using the current time.
// For production use, replace with a proper UUID library.
func generateURN() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		now&0xFFFFFFFF,
		(now>>32)&0xFFFF,
		0x4000|((now>>48)&0x0FFF),
		0x8000|(now&0x3FFF),
		now&0xFFFFFFFFFFFF,
	)
}
