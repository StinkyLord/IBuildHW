package strategies

import (
	"path/filepath"
	"runtime"
	"testing"
)

// testdataDir returns the absolute path to testdata/strategies.
func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	// file = .../internal/strategies/strategies_test.go
	// go up two levels to repo root, then into testdata/strategies
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "testdata", "strategies")
}

// ---- helpers ----

func findComponent(comps interface{ getComponents() []*componentLike }, name string) *componentLike {
	return nil
}

type componentLike struct {
	Name     string
	Version  string
	Channel  string
	Revision string
}

// ============================================================
// Conan: conanfile.txt
// ============================================================

func TestConanfileTxt_RequiresSection(t *testing.T) {
	dir := testdataDir()
	strat := &ConanStrategy{}
	result := strat.ScanWithGraph(dir, false)

	byName := map[string]bool{}
	for _, c := range result.Components {
		byName[c.Name] = true
	}

	// All four [requires] entries must be detected
	for _, want := range []string{"boost", "openssl", "zlib", "nlohmann_json"} {
		if !byName[want] {
			t.Errorf("conanfile.txt: expected component %q not found; got %v", want, keys(byName))
		}
	}
}

func TestConanfileTxt_BuildRequiresSection(t *testing.T) {
	dir := testdataDir()
	strat := &ConanStrategy{}
	result := strat.ScanWithGraph(dir, false)

	byName := map[string]bool{}
	for _, c := range result.Components {
		byName[c.Name] = true
	}

	// [build_requires] entries must also be detected
	for _, want := range []string{"cmake", "ninja"} {
		if !byName[want] {
			t.Errorf("conanfile.txt [build_requires]: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestConanfileTxt_DirectNames(t *testing.T) {
	dir := testdataDir()
	strat := &ConanStrategy{}
	result := strat.ScanWithGraph(dir, false)

	// Everything in [requires] and [build_requires] is direct
	for _, want := range []string{"boost", "openssl", "zlib", "nlohmann_json", "cmake", "ninja"} {
		if !result.DirectNames[want] {
			t.Errorf("conanfile.txt: %q should be in DirectNames; DirectNames=%v", want, result.DirectNames)
		}
	}
}

func TestConanfileTxt_Channel(t *testing.T) {
	// Parse conanfile.txt directly (not the whole dir) to avoid merging with other files
	txtPath := filepath.Join(testdataDir(), "conanfile.txt")
	comps, _ := parseConanfileTxtWithDirect(txtPath)

	// openssl/3.1.4@conan/stable — channel should be captured
	for _, c := range comps {
		if c.Name == "openssl" {
			if c.Channel != "conan/stable" {
				t.Errorf("openssl channel = %q, want %q", c.Channel, "conan/stable")
			}
			if c.Version != "3.1.4" {
				t.Errorf("openssl version = %q, want %q", c.Version, "3.1.4")
			}
			if c.PURL == "" {
				t.Error("openssl PURL is empty")
			}
			return
		}
	}
	t.Error("openssl not found in conanfile.txt components")
}

func TestConanfileTxt_Revision(t *testing.T) {
	// Parse conanfile.txt directly to avoid merging with conan.lock (which has no revision for zlib)
	txtPath := filepath.Join(testdataDir(), "conanfile.txt")
	comps, _ := parseConanfileTxtWithDirect(txtPath)

	// zlib/1.2.13#abc123def456 — revision should be captured
	for _, c := range comps {
		if c.Name == "zlib" {
			if c.Revision != "abc123def456" {
				t.Errorf("zlib revision = %q, want %q", c.Revision, "abc123def456")
			}
			return
		}
	}
	t.Error("zlib not found in conanfile.txt components")
}

// ============================================================
// Conan: conanfile.py
// ============================================================

func TestConanfilePy_SelfRequires(t *testing.T) {
	dir := testdataDir()
	strat := &ConanStrategy{}
	result := strat.ScanWithGraph(dir, false)

	byName := map[string]bool{}
	for _, c := range result.Components {
		byName[c.Name] = true
	}

	// self.requires(...) calls
	for _, want := range []string{"openssl", "zlib"} {
		if !byName[want] {
			t.Errorf("conanfile.py self.requires: expected %q not found", want)
		}
	}
}

func TestConanfilePy_BuildRequires(t *testing.T) {
	dir := testdataDir()
	strat := &ConanStrategy{}
	result := strat.ScanWithGraph(dir, false)

	byName := map[string]bool{}
	for _, c := range result.Components {
		byName[c.Name] = true
	}

	// self.build_requires(...)
	if !byName["cmake"] {
		t.Errorf("conanfile.py self.build_requires: expected cmake not found; got %v", keys(byName))
	}
}

func TestConanfilePy_PythonRequires(t *testing.T) {
	dir := testdataDir()
	strat := &ConanStrategy{}
	result := strat.ScanWithGraph(dir, false)

	byName := map[string]bool{}
	for _, c := range result.Components {
		byName[c.Name] = true
	}

	// python_requires = "cmake-conan/0.17.0@conan/stable"
	if !byName["cmake-conan"] {
		t.Errorf("conanfile.py python_requires: expected cmake-conan not found; got %v", keys(byName))
	}
}

func TestConanfilePy_ListSyntax(t *testing.T) {
	dir := testdataDir()
	strat := &ConanStrategy{}
	result := strat.ScanWithGraph(dir, false)

	byName := map[string]bool{}
	for _, c := range result.Components {
		byName[c.Name] = true
	}

	// requires = ["fmt/10.1.1", "spdlog/1.12.0"]
	for _, want := range []string{"fmt", "spdlog"} {
		if !byName[want] {
			t.Errorf("conanfile.py list syntax: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestConanfilePy_RevisionInSelfRequires(t *testing.T) {
	dir := testdataDir()
	strat := &ConanStrategy{}
	result := strat.ScanWithGraph(dir, false)

	// openssl/3.1.4@conan/stable#deadbeef1234
	for _, c := range result.Components {
		if c.Name == "openssl" && c.Revision == "deadbeef1234" {
			return // found with correct revision
		}
	}
	// openssl may appear multiple times (from txt and py); check at least one has the revision
	for _, c := range result.Components {
		if c.Name == "openssl" {
			t.Logf("openssl found with revision=%q channel=%q", c.Revision, c.Channel)
		}
	}
	t.Error("no openssl component with revision=deadbeef1234 found from conanfile.py")
}

// ============================================================
// Conan: conan.lock (v1 graph format)
// ============================================================

func TestConanLockV1_Components(t *testing.T) {
	dir := testdataDir()
	strat := &ConanStrategy{}
	result := strat.ScanWithGraph(dir, false)

	byName := map[string]bool{}
	for _, c := range result.Components {
		byName[c.Name] = true
	}

	// conan.lock has boost, openssl, zlib (node 0 = project root, skipped)
	for _, want := range []string{"boost", "openssl", "zlib"} {
		if !byName[want] {
			t.Errorf("conan.lock: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestConanLockV1_DirectNames(t *testing.T) {
	// Parse only the lock file directly to test graph edges
	lockPath := filepath.Join(testdataDir(), "conan.lock")
	result := parseConanLockWithGraph(lockPath)

	// Node "0" requires nodes "1" (boost) and "2" (openssl) → both are direct
	if !result.DirectNames["boost"] {
		t.Errorf("conan.lock: boost should be direct; DirectNames=%v", result.DirectNames)
	}
	if !result.DirectNames["openssl"] {
		t.Errorf("conan.lock: openssl should be direct; DirectNames=%v", result.DirectNames)
	}
	// zlib is only required by boost and openssl, not by node "0" → transitive
	if result.DirectNames["zlib"] {
		t.Errorf("conan.lock: zlib should be transitive (not in DirectNames)")
	}
}

func TestConanLockV1_Edges(t *testing.T) {
	lockPath := filepath.Join(testdataDir(), "conan.lock")
	result := parseConanLockWithGraph(lockPath)

	// boost → zlib
	boostDeps := result.Edges["boost"]
	found := false
	for _, d := range boostDeps {
		if d == "zlib" {
			found = true
		}
	}
	if !found {
		t.Errorf("conan.lock: expected boost→zlib edge; boost edges=%v", boostDeps)
	}

	// openssl → zlib
	opensslDeps := result.Edges["openssl"]
	found = false
	for _, d := range opensslDeps {
		if d == "zlib" {
			found = true
		}
	}
	if !found {
		t.Errorf("conan.lock: expected openssl→zlib edge; openssl edges=%v", opensslDeps)
	}
}

func TestConanLockV1_Revision(t *testing.T) {
	lockPath := filepath.Join(testdataDir(), "conan.lock")
	result := parseConanLockWithGraph(lockPath)

	// boost/1.82.0#rev001 — revision should be captured
	for _, c := range result.Components {
		if c.Name == "boost" {
			if c.Revision != "rev001" {
				t.Errorf("conan.lock boost revision = %q, want %q", c.Revision, "rev001")
			}
			return
		}
	}
	t.Error("boost not found in conan.lock components")
}

// ============================================================
// Header scan strategy
// ============================================================

func TestHeaderScan_DetectsThirdParty(t *testing.T) {
	dir := testdataDir()
	strat := &HeadersStrategy{}
	comps, err := strat.Scan(dir, false)
	if err != nil {
		t.Fatalf("HeadersStrategy.Scan failed: %v", err)
	}

	byName := map[string]bool{}
	for _, c := range comps {
		byName[c.Name] = true
	}

	// boost, openssl, nlohmann-json (fingerprint DB uses hyphen), spdlog should be detected from main.cpp
	for _, want := range []string{"boost", "openssl", "nlohmann-json"} {
		if !byName[want] {
			t.Errorf("header-scan: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestHeaderScan_IgnoresStdlib(t *testing.T) {
	dir := testdataDir()
	strat := &HeadersStrategy{}
	comps, err := strat.Scan(dir, false)
	if err != nil {
		t.Fatalf("HeadersStrategy.Scan failed: %v", err)
	}

	byName := map[string]bool{}
	for _, c := range comps {
		byName[c.Name] = true
	}

	// Standard library headers must NOT appear
	for _, bad := range []string{"vector", "string", "iostream", "algorithm", "cstdint"} {
		if byName[bad] {
			t.Errorf("header-scan: stdlib header %q should not be reported as a dependency", bad)
		}
	}
}

func TestHeaderScan_IgnoresInternalHeaders(t *testing.T) {
	dir := testdataDir()
	strat := &HeadersStrategy{}
	comps, err := strat.Scan(dir, false)
	if err != nil {
		t.Fatalf("HeadersStrategy.Scan failed: %v", err)
	}

	byName := map[string]bool{}
	for _, c := range comps {
		byName[c.Name] = true
	}

	// internal_utils.h is a quoted include that exists in the project — must not appear
	if byName["internal_utils"] {
		t.Error("header-scan: internal_utils.h should not be reported as a third-party dependency")
	}
}

func TestHeaderScan_DetectionSource(t *testing.T) {
	dir := testdataDir()
	strat := &HeadersStrategy{}
	comps, err := strat.Scan(dir, false)
	if err != nil {
		t.Fatalf("HeadersStrategy.Scan failed: %v", err)
	}

	for _, c := range comps {
		if c.DetectionSource != "header-scan" {
			t.Errorf("component %q has DetectionSource=%q, want %q", c.Name, c.DetectionSource, "header-scan")
		}
	}
}

// ============================================================
// compile_commands.json strategy
// ============================================================

func TestCompileCommands_DetectsExternalIncludes(t *testing.T) {
	dir := testdataDir()
	strat := &CompileCommandsStrategy{}
	comps, err := strat.Scan(dir, false)
	if err != nil {
		t.Fatalf("CompileCommandsStrategy.Scan failed: %v", err)
	}

	byName := map[string]bool{}
	for _, c := range comps {
		byName[c.Name] = true
	}

	// /usr/local/include/boost_1_82_0 → boost
	// /usr/include/openssl → openssl
	// /opt/local/include/zlib-1.2.13 → zlib
	for _, want := range []string{"boost", "openssl", "zlib"} {
		if !byName[want] {
			t.Errorf("compile_commands: expected %q not found; got %v", want, keys(byName))
		}
	}
}

func TestCompileCommands_ExtractsVersionFromPath(t *testing.T) {
	dir := testdataDir()
	strat := &CompileCommandsStrategy{}
	comps, err := strat.Scan(dir, false)
	if err != nil {
		t.Fatalf("CompileCommandsStrategy.Scan failed: %v", err)
	}

	for _, c := range comps {
		switch c.Name {
		case "boost":
			if c.Version != "1.82.0" {
				t.Errorf("boost version = %q, want %q (from path boost_1_82_0)", c.Version, "1.82.0")
			}
		case "zlib":
			if c.Version != "1.2.13" {
				t.Errorf("zlib version = %q, want %q (from path zlib-1.2.13)", c.Version, "1.2.13")
			}
		}
	}
}

func TestCompileCommands_IgnoresInternalPaths(t *testing.T) {
	dir := testdataDir()
	strat := &CompileCommandsStrategy{}
	comps, err := strat.Scan(dir, false)
	if err != nil {
		t.Fatalf("CompileCommandsStrategy.Scan failed: %v", err)
	}

	// /home/user/project/src and /home/user/project/include are "internal" paths
	// (they are under the project root in the compile command).
	// They should not produce components unless they match a fingerprint.
	// The key check: no component should have an include path that is inside the project root.
	for _, c := range comps {
		for _, ip := range c.IncludePaths {
			if ip == "/home/user/project/src" || ip == "/home/user/project/include" {
				t.Errorf("component %q has internal include path %q — should be filtered", c.Name, ip)
			}
		}
	}
}

// ============================================================
// conanRefToComponent unit tests
// ============================================================

func TestConanRefToComponent_Simple(t *testing.T) {
	c := conanRefToComponent("boost/1.82.0", "conan")
	if c == nil {
		t.Fatal("conanRefToComponent returned nil for simple ref")
	}
	if c.Name != "boost" {
		t.Errorf("name = %q, want %q", c.Name, "boost")
	}
	if c.Version != "1.82.0" {
		t.Errorf("version = %q, want %q", c.Version, "1.82.0")
	}
	if c.Channel != "" {
		t.Errorf("channel = %q, want empty", c.Channel)
	}
	if c.Revision != "" {
		t.Errorf("revision = %q, want empty", c.Revision)
	}
}

func TestConanRefToComponent_WithChannel(t *testing.T) {
	c := conanRefToComponent("openssl/3.1.4@conan/stable", "conan")
	if c == nil {
		t.Fatal("conanRefToComponent returned nil")
	}
	if c.Channel != "conan/stable" {
		t.Errorf("channel = %q, want %q", c.Channel, "conan/stable")
	}
	// PURL should contain channel qualifier
	if c.PURL == "" {
		t.Error("PURL is empty")
	}
}

func TestConanRefToComponent_WithRevision(t *testing.T) {
	c := conanRefToComponent("zlib/1.2.13#abc123", "conan")
	if c == nil {
		t.Fatal("conanRefToComponent returned nil")
	}
	if c.Revision != "abc123" {
		t.Errorf("revision = %q, want %q", c.Revision, "abc123")
	}
}

func TestConanRefToComponent_WithChannelAndRevision(t *testing.T) {
	c := conanRefToComponent("openssl/3.1.4@conan/stable#deadbeef", "conan")
	if c == nil {
		t.Fatal("conanRefToComponent returned nil")
	}
	if c.Channel != "conan/stable" {
		t.Errorf("channel = %q, want %q", c.Channel, "conan/stable")
	}
	if c.Revision != "deadbeef" {
		t.Errorf("revision = %q, want %q", c.Revision, "deadbeef")
	}
}

func TestConanRefToComponent_Invalid(t *testing.T) {
	// No slash → should return nil
	c := conanRefToComponent("notaref", "conan")
	if c != nil {
		t.Errorf("expected nil for invalid ref, got %+v", c)
	}
}

func TestConanRefToComponent_PlaceholderChannel(t *testing.T) {
	// @_/_ is Conan's "no channel" placeholder — should not appear in PURL
	c := conanRefToComponent("boost/1.82.0@_/_", "conan")
	if c == nil {
		t.Fatal("conanRefToComponent returned nil")
	}
	// Channel should be stored but PURL should not include it
	if c.Channel != "_/_" {
		t.Errorf("channel = %q, want %q", c.Channel, "_/_")
	}
	// PURL must NOT contain "?channel="
	if len(c.PURL) > 0 {
		for _, ch := range []string{"?channel=", "_/_"} {
			if len(c.PURL) > 0 && containsStr(c.PURL, ch) {
				t.Errorf("PURL %q should not contain placeholder channel %q", c.PURL, ch)
			}
		}
	}
}

// ============================================================
// extractVersionFromPath unit tests
// ============================================================

func TestExtractVersionFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/usr/local/include/boost_1_82_0", "1.82.0"},
		{"/opt/local/include/zlib-1.2.13", "1.2.13"},
		{"/usr/include/openssl-3.1.4", "3.1.4"},
		{"/usr/include/openssl", ""},   // no version in path
		{"/home/user/project/src", ""}, // no version
		{"/opt/fmt-10.1.1/include", "10.1.1"},
	}

	for _, tc := range cases {
		got := extractVersionFromPath(tc.path)
		if got != tc.want {
			t.Errorf("extractVersionFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// ============================================================
// helpers
// ============================================================

func keys(m map[string]bool) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
