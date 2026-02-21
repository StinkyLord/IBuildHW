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

	tree.Roots = tree.buildTree()
	return tree
}

// workItem holds a pending node to be expanded along with the set of ancestor
// keys on the path from the root to this node (used for cycle detection).
type workItem struct {
	comp      *Component
	node      *TreeNode
	ancestors map[string]bool
}

// buildTree builds the npm-style dependency tree iteratively, level by level,
// using a queue (slice) instead of recursion. This avoids stack overflows on
// very deep or wide dependency graphs.
//
// Only direct dependencies appear at the root. Each node carries its full
// subtree of children. Cycles are broken by tracking the ancestor set on the
// path from the root to the current node — if a child would create a cycle it
// is emitted as a leaf (no children).
func (t *DependencyTree) buildTree() []*TreeNode {
	// Sort direct deps for deterministic output.
	directs := make([]*Component, len(t.Direct))
	copy(directs, t.Direct)
	sort.Slice(directs, func(i, j int) bool {
		return directs[i].Name < directs[j].Name
	})

	roots := make([]*TreeNode, 0, len(directs))

	// queue holds all nodes whose children still need to be resolved.
	queue := make([]workItem, 0, len(directs))

	// Build the root level (level 0).
	for _, c := range directs {
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
		roots = append(roots, node)

		// Each root gets its own ancestor set so sibling paths are independent.
		ancestors := map[string]bool{c.Key(): true}
		queue = append(queue, workItem{comp: c, node: node, ancestors: ancestors})
	}

	// Process the queue level by level (BFS order).
	// Each iteration pops the front item, resolves its children, and enqueues
	// those children for further expansion.
	for len(queue) > 0 {
		// Dequeue the front item.
		item := queue[0]
		queue = queue[1:]

		// Sort children for deterministic output.
		childNames := make([]string, len(item.comp.Dependencies))
		copy(childNames, item.comp.Dependencies)
		sort.Strings(childNames)

		for _, childName := range childNames {
			childComp := t.ByName[normalizeKey(childName)]
			if childComp == nil {
				// Referenced in an edge but not in the component list —
				// emit a placeholder leaf node (no further expansion needed).
				item.node.Children = append(item.node.Children, &TreeNode{
					Name:           childName,
					Version:        "unknown",
					PURL:           "pkg:generic/" + childName,
					DependencyType: "transitive",
				})
				continue
			}

			childDepType := "transitive"
			if childComp.IsDirect {
				childDepType = "direct"
			}

			childNode := &TreeNode{
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
			}
			item.node.Children = append(item.node.Children, childNode)

			childKey := childComp.Key()
			if item.ancestors[childKey] {
				// Cycle detected — emit as a leaf to break the cycle.
				// Do NOT enqueue for further expansion.
				continue
			}

			// Build a new ancestor set for this child's path by copying the
			// parent's set and adding the child's key.
			childAncestors := make(map[string]bool, len(item.ancestors)+1)
			for k := range item.ancestors {
				childAncestors[k] = true
			}
			childAncestors[childKey] = true

			queue = append(queue, workItem{comp: childComp, node: childNode, ancestors: childAncestors})
		}
	}

	return roots
}
