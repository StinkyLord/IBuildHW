package model

import "sort"

// TreeNode is a single node in the recursive dependency tree.
// Each node carries its full subtree of children inline — like npm's
// package-lock.json — so the tree can be rendered at any depth.
//
// All component metadata (detection source, include paths, link libraries, etc.)
// is embedded directly in each node so the tree is self-contained.
//
// Example:
//
//	X@1 -> children: [A@1 -> children: [B@1]]
//	Y@1 -> children: [C@1 -> children: [A@1 -> children: [B@1]]]
type TreeNode struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	PURL            string      `json:"purl,omitempty"`
	DependencyType  string      `json:"dependencyType"` // "direct" or "transitive"
	Description     string      `json:"description,omitempty"`
	DetectionSource string      `json:"detectionSource,omitempty"`
	Revision        string      `json:"revision,omitempty"`
	Channel         string      `json:"channel,omitempty"`
	IncludePaths    []string    `json:"includePaths,omitempty"`
	LinkLibraries   []string    `json:"linkLibraries,omitempty"`
	Children        []*TreeNode `json:"children,omitempty"`
}

// DependencyTree holds the full dependency hierarchy for a scanned project.
type DependencyTree struct {
	// Direct contains components that the project itself explicitly depends on.
	Direct []*Component

	// Transitive contains components that are dependencies of direct dependencies.
	Transitive []*Component

	// All is the union of Direct and Transitive, deduplicated.
	All []*Component

	// ByName provides O(1) lookup of any component by its lowercase name.
	ByName map[string]*Component

	// Roots is the recursive tree: only direct dependencies at the top level,
	// each carrying their full subtree of children.
	// This is the npm package-lock.json style tree.
	Roots []*TreeNode
}

func BuildDependencyTree(components []*Component) *DependencyTree {
	tree := &DependencyTree{
		ByName: make(map[string]*Component, len(components)),
	}

	for _, c := range components {
		tree.All = append(tree.All, c)
		tree.ByName[normalizeKey(c.Name)] = c
		tree.ByName[c.Name] = c

		if c.IsDirect {
			tree.Direct = append(tree.Direct, c)
		} else {
			tree.Transitive = append(tree.Transitive, c)
		}
	}

	tree.Roots = tree.buildRecursiveTree()
	return tree
}

// buildRecursiveTree builds the npm-style recursive dependency tree.
// Only direct dependencies appear at the root. Each node carries its full
// subtree of children. Cycles are broken by tracking the current path
// (ancestor set) — if a node would create a cycle, it is emitted as a
// leaf (no children) to avoid infinite recursion.
func (t *DependencyTree) buildRecursiveTree() []*TreeNode {
	// Sort direct deps for deterministic output
	directs := make([]*Component, len(t.Direct))
	copy(directs, t.Direct)
	sort.Slice(directs, func(i, j int) bool {
		return directs[i].Name < directs[j].Name
	})

	roots := make([]*TreeNode, 0, len(directs))
	for _, c := range directs {
		ancestors := map[string]bool{}
		roots = append(roots, t.buildNode(c, ancestors))
	}
	return roots
}

// buildNode recursively builds a TreeNode for the given component.
// ancestors is the set of component keys on the current path from the root —
// used to detect and break cycles.
func (t *DependencyTree) buildNode(c *Component, ancestors map[string]bool) *TreeNode {
	depType := "transitive"
	if c.IsDirect {
		depType = "direct"
	}

	node := &TreeNode{
		Name:            c.Name,
		Version:         c.Version,
		PURL:            c.PURL,
		DependencyType:  depType,
		Description:     c.Description,
		DetectionSource: c.DetectionSource,
		Revision:        c.Revision,
		Channel:         c.Channel,
		IncludePaths:    c.IncludePaths,
		LinkLibraries:   c.LinkLibraries,
	}

	// Mark this node as an ancestor for the current path
	key := c.Key()
	ancestors[key] = true
	defer func() { delete(ancestors, key) }()

	// Sort children for deterministic output
	childNames := make([]string, len(c.Dependencies))
	copy(childNames, c.Dependencies)
	sort.Strings(childNames)

	for _, childName := range childNames {
		childComp := t.ByName[normalizeKey(childName)]
		if childComp == nil {
			// Referenced in an edge but not in the component list —
			// emit a placeholder leaf node
			node.Children = append(node.Children, &TreeNode{
				Name:           childName,
				Version:        "unknown",
				PURL:           "pkg:generic/" + childName,
				DependencyType: "transitive",
			})
			continue
		}

		childKey := childComp.Key()
		if ancestors[childKey] {
			// Cycle detected — emit as a leaf to break the cycle
			childDepType := "transitive"
			if childComp.IsDirect {
				childDepType = "direct"
			}
			node.Children = append(node.Children, &TreeNode{
				Name:            childComp.Name,
				Version:         childComp.Version,
				PURL:            childComp.PURL,
				DependencyType:  childDepType,
				Description:     childComp.Description,
				DetectionSource: childComp.DetectionSource,
				Revision:        childComp.Revision,
				Channel:         childComp.Channel,
				IncludePaths:    childComp.IncludePaths,
				LinkLibraries:   childComp.LinkLibraries,
			})
			continue
		}

		node.Children = append(node.Children, t.buildNode(childComp, ancestors))
	}

	return node
}
