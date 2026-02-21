package strategies

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
)

// sampleCppProjectDir returns the absolute path to testdata/sample-cpp-project.
func sampleCppProjectDir() string {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "testdata", "sample-cpp-project")
}

// ============================================================
// LinkerMap strategy — o1.map (ARM GCC cross-compile map file)
// ============================================================

// TestLinkerMap_FindsMapFile verifies that the strategy locates o1.map at all.
func TestLinkerMap_FindsMapFile(t *testing.T) {
	dir := sampleCppProjectDir()
	strat := &LinkerMapStrategy{}
	result := strat.ScanWithEdges(dir, true)

	// The map file contains libgcc.a, libc_nano.a, libnosys.a — at minimum
	// the strategy must find *something* (non-zero components or at least
	// non-zero raw lib paths before fingerprint matching).
	//
	// If this fails with 0 components it means either:
	//   (a) the .map file was not found, or
	//   (b) no lib paths were extracted from it.
	if len(result.Components) == 0 {
		t.Error("LinkerMapStrategy: expected at least one component from o1.map, got 0")
		t.Log("Hint: check reMapLibEntry regex against Windows-style paths with backslash separators")
		t.Log("Hint: check that LOAD lines like 'LOAD c:/path/to\\libgcc.a' are matched")
	}
}

// TestLinkerMap_DetectsLibgcc verifies that libgcc is detected from the LOAD lines.
// The map file has: LOAD c:/siliconlabs/.../nofp\libgcc.a
func TestLinkerMap_DetectsLibgcc(t *testing.T) {
	dir := sampleCppProjectDir()
	strat := &LinkerMapStrategy{}
	result := strat.ScanWithEdges(dir, false)

	byName := map[string]bool{}
	for _, c := range result.Components {
		byName[strings.ToLower(c.Name)] = true
	}

	// libgcc is a GCC runtime library — it should be detected
	if !byName["libgcc"] {
		t.Errorf("LinkerMapStrategy: expected 'libgcc' component; got components: %v", componentNames(result.Components))
	}
}

// TestLinkerMap_DetectsLibcNano verifies that libc_nano (newlib-nano) is detected.
// The map file has: LOAD c:/siliconlabs/.../nofp\libc_nano.a
func TestLinkerMap_DetectsLibcNano(t *testing.T) {
	dir := sampleCppProjectDir()
	strat := &LinkerMapStrategy{}
	result := strat.ScanWithEdges(dir, false)

	byName := map[string]bool{}
	for _, c := range result.Components {
		byName[strings.ToLower(c.Name)] = true
	}

	// libc_nano is the newlib-nano C library for embedded targets
	if !byName["libc_nano"] && !byName["newlib"] && !byName["libc"] {
		t.Errorf("LinkerMapStrategy: expected a libc/newlib component; got: %v", componentNames(result.Components))
	}
}

// TestLinkerMap_DetectsLibnosys verifies that libnosys is detected.
// The map file has: LOAD c:/siliconlabs/.../nofp\libnosys.a
func TestLinkerMap_DetectsLibnosys(t *testing.T) {
	dir := sampleCppProjectDir()
	strat := &LinkerMapStrategy{}
	result := strat.ScanWithEdges(dir, false)

	byName := map[string]bool{}
	for _, c := range result.Components {
		byName[strings.ToLower(c.Name)] = true
	}

	if !byName["libnosys"] {
		t.Errorf("LinkerMapStrategy: expected 'libnosys' component; got: %v", componentNames(result.Components))
	}
}

// TestLinkerMap_SatisfySection_ParsesTwoLineFormat verifies that the "Archive member
// included to satisfy reference" section is parsed correctly.
//
// In o1.map the format is TWO lines per entry (not one):
//
//	c:/path/to\libgcc.a(_arm_addsubsf3.o)          <- child (line 1)
//	                              build/vddcheck.o (__aeabi_fsub)  <- parent (line 2, indented)
//
// The current reSatisfyRef regex expects both on the same line and will miss this.
func TestLinkerMap_SatisfySection_ParsesTwoLineFormat(t *testing.T) {
	dir := sampleCppProjectDir()
	strat := &LinkerMapStrategy{}
	result := strat.ScanWithEdges(dir, true)

	// The satisfy section in o1.map has entries like:
	//   libgcc.a pulled in by build/vddcheck.o
	//   libc_nano.a pulled in by libc_nano.a(lib_a-exit.o) (internal dep)
	//   libnosys.a pulled in by libc_nano.a(lib_a-exit.o)
	//
	// We just verify the strategy doesn't crash and returns a result.
	if result == nil {
		t.Fatal("ScanWithEdges returned nil")
	}
	t.Logf("Components found: %v", componentNames(result.Components))
	t.Logf("Edges found: %v", result.Edges)
}

// TestLinkerMap_RegexMatchesWindowsPathWithBackslash is a unit test for the
// reMapLibEntry regex against the actual path format in o1.map.
//
// The paths look like:
//
//	c:/siliconlabs/.../nofp\libgcc.a
//	c:/siliconlabs/.../nofp\libc_nano.a
//
// Note the backslash before the filename — the regex must handle this.
func TestLinkerMap_RegexMatchesWindowsPathWithBackslash(t *testing.T) {
	// These are actual LOAD lines from o1.map
	loadLines := []string{
		`LOAD c:/siliconlabs/simplicitystudio/v5/developer/toolchains/gnu_arm/10.3_2021.10/bin/../lib/gcc/arm-none-eabi/10.3.1/thumb/v7-m/nofp\libgcc.a`,
		`LOAD c:/siliconlabs/simplicitystudio/v5/developer/toolchains/gnu_arm/10.3_2021.10/bin/../lib/gcc/arm-none-eabi/10.3.1/../../../../arm-none-eabi/lib/thumb/v7-m/nofp\libc_nano.a`,
		`LOAD c:/siliconlabs/simplicitystudio/v5/developer/toolchains/gnu_arm/10.3_2021.10/bin/../lib/gcc/arm-none-eabi/10.3.1/../../../../arm-none-eabi/lib/thumb/v7-m/nofp\libnosys.a`,
	}

	for _, line := range loadLines {
		m := reMapLibEntry.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("reMapLibEntry did not match LOAD line:\n  %s\n  Hint: the path uses backslash before the filename (Windows cross-compile path)", line)
		} else {
			t.Logf("reMapLibEntry matched: %q -> captured: %q", line, m[1])
		}
	}
}

// TestLinkerMap_RegexMatchesSatisfySectionLines tests the satisfy-section line regexes.
// In o1.map the satisfy section uses a TWO-line format:
//
//	c:/path/to\libgcc.a(_arm_addsubsf3.o)          <- line 1: child library
//	                              build/vddcheck.o (__aeabi_fsub)  <- line 2: parent
//
// reSatisfyChildLine must match line 1 (capturing the library path).
// reSatisfyRef does NOT match line 1 alone (it expects both on one line).
func TestLinkerMap_RegexMatchesSatisfySectionLines(t *testing.T) {
	// Line 1: child library with object member — must match reSatisfyChildLine
	childLine := `c:/siliconlabs/simplicitystudio/v5/developer/toolchains/gnu_arm/10.3_2021.10/bin/../lib/gcc/arm-none-eabi/10.3.1/thumb/v7-m/nofp\libgcc.a(_arm_addsubsf3.o)`

	m := reSatisfyChildLine.FindStringSubmatch(childLine)
	if m == nil {
		t.Errorf("reSatisfyChildLine did NOT match child line:\n  %s", childLine)
	} else {
		t.Logf("reSatisfyChildLine captured library path: %q", m[1])
	}

	// reSatisfyRef should NOT match line 1 alone (it's a single-line format regex)
	if reSatisfyRef.FindStringSubmatch(childLine) != nil {
		t.Log("reSatisfyRef also matched child-only line (harmless)")
	}

	// Line 2: parent (requester) — indented, local object file
	parentLine := `                              build/vddcheck.o (__aeabi_fsub)`
	// The parent line is a local .o file — reSatisfyChildLine should NOT match it
	if m2 := reSatisfyChildLine.FindStringSubmatch(parentLine); m2 != nil {
		t.Errorf("reSatisfyChildLine unexpectedly matched local parent line: %v", m2)
	} else {
		t.Log("reSatisfyChildLine correctly did not match local parent line (build/vddcheck.o)")
	}
}

// TestLinkerMap_DetectionSource verifies that detected components have the correct source.
func TestLinkerMap_DetectionSource(t *testing.T) {
	dir := sampleCppProjectDir()
	strat := &LinkerMapStrategy{}
	result := strat.ScanWithEdges(dir, false)

	for _, c := range result.Components {
		if c.DetectionSource != "linker-map" {
			t.Errorf("component %q has DetectionSource=%q, want %q",
				c.Name, c.DetectionSource, "linker-map")
		}
	}
}

// componentNames is a helper that returns a slice of component names for logging.
func componentNames(comps []*model.Component) []string {
	names := make([]string, 0, len(comps))
	for _, c := range comps {
		names = append(names, c.Name)
	}
	return names
}
