package model

import "sort"

type HierarchyLevel struct {
	Depth      int          // 0-based depth (0 = direct)
	Components []*Component // components at this depth, sorted by name
}

// DependencyTree holds the full dependency hierarchy for a scanned project.
// It separates components into direct (explicitly used by the project) and
// transitive (pulled in by a direct dependency) categories, and records the
// parent→child edges so a full tree can be rendered.
type DependencyTree struct {
	// Direct contains components that the project itself explicitly depends on.
	// These are declared in the project's own manifests (conanfile, vcpkg.json,
	// CMakeLists find_package, compile_commands -I paths, etc.).
	Direct []*Component

	// Transitive contains components that are dependencies of direct dependencies
	// (or deeper). The project does not reference them directly.
	Transitive []*Component

	// All is the union of Direct and Transitive, deduplicated.
	All []*Component

	// ByName provides O(1) lookup of any component by its lowercase name.
	ByName map[string]*Component

	// Levels is the full BFS hierarchy: Levels[0] = direct deps,
	// Levels[1] = their children, Levels[2] = grandchildren, etc.
	// Built by BuildHierarchy().
	Levels []HierarchyLevel
}

func BuildDependencyTree(components []*Component) *DependencyTree {
	tree := &DependencyTree{
		ByName: make(map[string]*Component, len(components)),
	}

	for _, c := range components {
		tree.All = append(tree.All, c)
		// Index by both original name and normalised key
		tree.ByName[normalizeKey(c.Name)] = c
		tree.ByName[c.Name] = c

		if c.IsDirect {
			tree.Direct = append(tree.Direct, c)
		} else {
			tree.Transitive = append(tree.Transitive, c)
		}
	}

	tree.BuildHierarchy()
	return tree
}

// BuildHierarchy performs a BFS (breadth-first) traversal of the dependency
// graph starting from the direct dependencies (level 0).
//
// It uses an explicit queue — no recursion — so it is safe for arbitrarily
// deep or wide graphs. Cycles are handled by a visited set keyed on
// "name@version" so that two different versions of the same library (e.g.
// X@1.0 and X@2.0) are treated as distinct nodes. Each node appears at most
// once — at its shallowest depth.
//
// The result is stored in tree.Levels.
func (t *DependencyTree) BuildHierarchy() {
	t.Levels = nil
	if len(t.Direct) == 0 {
		return
	}

	// visited tracks which "name@version" nodes have already been placed.
	// We use Component.Key() which normalises the name and appends @version,
	// so X@1.0 and X@2.0 are distinct while "nlohmann_json" == "nlohmann-json".
	visited := make(map[string]bool, len(t.All))

	// queue holds the components waiting to be processed (FIFO).
	type queueItem struct {
		comp  *Component
		depth int
	}

	queue := make([]queueItem, 0, len(t.Direct))

	// Seed the queue with all direct dependencies (depth 0)
	// Sort for deterministic output.
	directComps := make([]*Component, len(t.Direct))
	copy(directComps, t.Direct)
	sort.Slice(directComps, func(i, j int) bool {
		return directComps[i].Key() < directComps[j].Key()
	})

	for _, c := range directComps {
		if !visited[c.Key()] {
			visited[c.Key()] = true
			queue = append(queue, queueItem{comp: c, depth: 0})
		}
	}

	for len(queue) > 0 {

		// Dequeue.
		item := queue[0]
		queue = queue[1:]

		comp := item.comp

		// Grow the Levels slice if needed.
		for len(t.Levels) <= item.depth {
			t.Levels = append(t.Levels, HierarchyLevel{Depth: len(t.Levels)})
		}
		t.Levels[item.depth].Components = append(t.Levels[item.depth].Components, comp)

		// Enqueue children (sorted for determinism), skipping already-visited ones.
		childNames := make([]string, len(comp.Dependencies))
		copy(childNames, comp.Dependencies)
		sort.Strings(childNames)

		for _, childName := range childNames {
			// Look up the child component by name.
			childComp := t.ByName[normalizeKey(childName)]
			if childComp == nil {
				// Referenced in an edge but not in the component list —
				// create a placeholder so the tree is complete.
				childComp = &Component{
					Name:    childName,
					Version: "unknown",
					PURL:    "pkg:generic/" + childName,
				}
			}
			if !visited[childComp.Key()] {
				visited[childComp.Key()] = true
				queue = append(queue, queueItem{comp: childComp, depth: item.depth + 1})
			}
		}
	}
}
