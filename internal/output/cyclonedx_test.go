package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
	"github.com/StinkyLord/cpp-sbom-builder/internal/scanner"
)

// makeTestResult builds a synthetic scanner.Result for testing.
// boost and openssl are DIRECT; zlib is TRANSITIVE (pulled in by openssl).
// openssl declares zlib as a child dependency.
func makeTestResult() *scanner.Result {
	boost := &model.Component{
		Name:            "boost",
		Version:         "1.82.0",
		PURL:            "pkg:conan/boost@1.82.0",
		DetectionSource: "conan",
		Description:     "Boost C++ Libraries",
		IncludePaths:    []string{"/usr/include/boost"},
		LinkLibraries:   []string{"boost_system", "boost_filesystem"},
		IsDirect:        true,
		Dependencies:    []string{},
	}
	openssl := &model.Component{
		Name:            "openssl",
		Version:         "3.1.4",
		PURL:            "pkg:conan/openssl@3.1.4",
		DetectionSource: "compile_commands.json",
		Description:     "OpenSSL cryptography library",
		IncludePaths:    []string{"/usr/include/openssl"},
		LinkLibraries:   []string{"ssl", "crypto"},
		IsDirect:        true,
		Dependencies:    []string{"zlib"}, // openssl depends on zlib
	}
	zlib := &model.Component{
		Name:            "zlib",
		Version:         "1.2.13",
		PURL:            "pkg:conan/zlib@1.2.13",
		DetectionSource: "conan",
		Description:     "zlib compression library",
		IsDirect:        false, // transitive — pulled in by openssl
		Dependencies:    []string{},
	}
	nlohmann := &model.Component{
		Name:            "nlohmann-json",
		Version:         "unknown",
		PURL:            "pkg:github/nlohmann/json",
		DetectionSource: "header-scan",
		Description:     "JSON for Modern C++",
		IsDirect:        true,
		Dependencies:    []string{},
	}

	components := []*model.Component{boost, openssl, zlib, nlohmann}
	tree := model.BuildDependencyTree(components)

	return &scanner.Result{
		Components:        components,
		DependencyTree:    tree,
		StrategiesUsed:    []string{"conan", "compile_commands.json", "header-scan"},
		StrategiesSkipped: []string{"vcpkg", "meson", "linker-map"},
	}
}

// TestCycloneDXSchema verifies that the output is valid JSON and contains the
// required CycloneDX 1.4 top-level fields.
func TestCycloneDXSchema(t *testing.T) {
	result := makeTestResult()

	tmp := filepath.Join(t.TempDir(), "sbom.json")
	if err := WriteCycloneDX(result, tmp, "1.0.0-test"); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("cannot read output file: %v", err)
	}

	// Must be valid JSON
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v\nContent:\n%s", err, string(data))
	}

	// Required top-level fields
	requiredFields := []string{"bomFormat", "specVersion", "version", "serialNumber", "metadata", "components"}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing required field %q in CycloneDX output", field)
		}
	}

	// bomFormat must be "CycloneDX"
	var bomFormat string
	if err := json.Unmarshal(raw["bomFormat"], &bomFormat); err != nil || bomFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want %q", bomFormat, "CycloneDX")
	}

	// specVersion must be "1.4"
	var specVersion string
	if err := json.Unmarshal(raw["specVersion"], &specVersion); err != nil || specVersion != "1.4" {
		t.Errorf("specVersion = %q, want %q", specVersion, "1.4")
	}

	// serialNumber must start with "urn:uuid:"
	var serialNumber string
	if err := json.Unmarshal(raw["serialNumber"], &serialNumber); err != nil || !strings.HasPrefix(serialNumber, "urn:uuid:") {
		t.Errorf("serialNumber = %q, want prefix %q", serialNumber, "urn:uuid:")
	}
}

// TestCycloneDXComponents verifies that all input components appear in the output.
func TestCycloneDXComponents(t *testing.T) {
	result := makeTestResult()

	tmp := filepath.Join(t.TempDir(), "sbom.json")
	if err := WriteCycloneDX(result, tmp, "1.0.0-test"); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("cannot read output file: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("cannot unmarshal CycloneDX BOM: %v", err)
	}

	if len(bom.Components) != len(result.Components) {
		t.Errorf("component count = %d, want %d", len(bom.Components), len(result.Components))
	}

	byName := map[string]cdxComponent{}
	for _, c := range bom.Components {
		byName[c.Name] = c
	}

	// Check boost
	boost, ok := byName["boost"]
	if !ok {
		t.Fatal("boost component missing from output")
	}
	if boost.Version != "1.82.0" {
		t.Errorf("boost version = %q, want %q", boost.Version, "1.82.0")
	}
	if boost.PURL != "pkg:conan/boost@1.82.0" {
		t.Errorf("boost PURL = %q, want %q", boost.PURL, "pkg:conan/boost@1.82.0")
	}
	if boost.Type != "library" {
		t.Errorf("boost type = %q, want %q", boost.Type, "library")
	}

	// Check openssl
	ssl, ok := byName["openssl"]
	if !ok {
		t.Fatal("openssl component missing from output")
	}
	if ssl.Version != "3.1.4" {
		t.Errorf("openssl version = %q, want %q", ssl.Version, "3.1.4")
	}

	// Check nlohmann-json (unknown version)
	nj, ok := byName["nlohmann-json"]
	if !ok {
		t.Fatal("nlohmann-json component missing from output")
	}
	if nj.Version != "unknown" {
		t.Errorf("nlohmann-json version = %q, want %q", nj.Version, "unknown")
	}

	// Check zlib (transitive)
	_, ok = byName["zlib"]
	if !ok {
		t.Fatal("zlib component missing from output")
	}
}

// TestCycloneDXDependencyType verifies that direct/transitive classification
// is correctly recorded in the sbom:dependencyType property.
func TestCycloneDXDependencyType(t *testing.T) {
	result := makeTestResult()

	tmp := filepath.Join(t.TempDir(), "sbom.json")
	if err := WriteCycloneDX(result, tmp, "1.0.0-test"); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("cannot read output file: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("cannot unmarshal CycloneDX BOM: %v", err)
	}

	byName := map[string]cdxComponent{}
	for _, c := range bom.Components {
		byName[c.Name] = c
	}

	getProp := func(comp cdxComponent, propName string) string {
		for _, p := range comp.Properties {
			if p.Name == propName {
				return p.Value
			}
		}
		return ""
	}

	// boost is direct
	if dt := getProp(byName["boost"], "sbom:dependencyType"); dt != "direct" {
		t.Errorf("boost dependencyType = %q, want %q", dt, "direct")
	}

	// openssl is direct
	if dt := getProp(byName["openssl"], "sbom:dependencyType"); dt != "direct" {
		t.Errorf("openssl dependencyType = %q, want %q", dt, "direct")
	}

	// zlib is transitive
	if dt := getProp(byName["zlib"], "sbom:dependencyType"); dt != "transitive" {
		t.Errorf("zlib dependencyType = %q, want %q", dt, "transitive")
	}

	// nlohmann-json is direct
	if dt := getProp(byName["nlohmann-json"], "sbom:dependencyType"); dt != "direct" {
		t.Errorf("nlohmann-json dependencyType = %q, want %q", dt, "direct")
	}
}

// TestCycloneDXDependenciesArray verifies that the top-level dependencies array
// correctly encodes the parent→child relationships.
func TestCycloneDXDependenciesArray(t *testing.T) {
	result := makeTestResult()

	tmp := filepath.Join(t.TempDir(), "sbom.json")
	if err := WriteCycloneDX(result, tmp, "1.0.0-test"); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("cannot read output file: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("cannot unmarshal CycloneDX BOM: %v", err)
	}

	// dependencies array must be present
	if len(bom.Dependencies) == 0 {
		t.Fatal("dependencies array is empty")
	}

	// Build a map: ref -> dependsOn
	depMap := map[string][]string{}
	for _, d := range bom.Dependencies {
		depMap[d.Ref] = d.DependsOn
	}

	// openssl should declare zlib as a child
	opensslDeps, ok := depMap["pkg:conan/openssl@3.1.4"]
	if !ok {
		t.Fatal("openssl not found in dependencies array")
	}
	foundZlib := false
	for _, dep := range opensslDeps {
		if dep == "pkg:conan/zlib@1.2.13" {
			foundZlib = true
		}
	}
	if !foundZlib {
		t.Errorf("openssl.dependsOn does not contain zlib; got %v", opensslDeps)
	}
}

// TestDependencyTree verifies the DependencyTree model directly.
func TestDependencyTree(t *testing.T) {
	result := makeTestResult()
	tree := result.DependencyTree

	if tree == nil {
		t.Fatal("DependencyTree is nil")
	}

	// Direct: boost, openssl, nlohmann-json (3 direct)
	if len(tree.Direct) != 3 {
		t.Errorf("Direct count = %d, want 3", len(tree.Direct))
	}

	// Transitive: zlib (1 transitive)
	if len(tree.Transitive) != 1 {
		t.Errorf("Transitive count = %d, want 1", len(tree.Transitive))
	}

	// All: 4 total
	if len(tree.All) != 4 {
		t.Errorf("All count = %d, want 4", len(tree.All))
	}

	// ByName lookup
	if tree.ByName["zlib"] == nil {
		t.Error("ByName[\"zlib\"] is nil")
	}
	if tree.ByName["boost"] == nil {
		t.Error("ByName[\"boost\"] is nil")
	}

	// Verify zlib is transitive
	if tree.ByName["zlib"].IsDirect {
		t.Error("zlib should be transitive (IsDirect=false)")
	}

	// Verify boost is direct
	if !tree.ByName["boost"].IsDirect {
		t.Error("boost should be direct (IsDirect=true)")
	}
}

// TestRecursiveTree verifies the npm-style recursive dependency tree model.
//
// Graph:
//
//	boost    (direct, no children)
//	openssl  (direct) → zlib (transitive)
//	nlohmann (direct, no children)
//
// Expected Roots (sorted): boost, nlohmann-json, openssl
// openssl.Children must contain zlib with its own (empty) children.
func TestRecursiveTree(t *testing.T) {
	result := makeTestResult()
	tree := result.DependencyTree

	if tree == nil {
		t.Fatal("DependencyTree is nil")
	}

	// Roots = direct deps only (3)
	if len(tree.Roots) != 3 {
		t.Fatalf("Roots count = %d, want 3", len(tree.Roots))
	}

	// Roots are sorted: boost, nlohmann-json, openssl
	if tree.Roots[0].Name != "boost" {
		t.Errorf("Roots[0].Name = %q, want boost", tree.Roots[0].Name)
	}
	if tree.Roots[1].Name != "nlohmann-json" {
		t.Errorf("Roots[1].Name = %q, want nlohmann-json", tree.Roots[1].Name)
	}
	if tree.Roots[2].Name != "openssl" {
		t.Errorf("Roots[2].Name = %q, want openssl", tree.Roots[2].Name)
	}

	// boost has no children
	if len(tree.Roots[0].Children) != 0 {
		t.Errorf("boost.Children count = %d, want 0", len(tree.Roots[0].Children))
	}

	// openssl has one child: zlib
	opensslNode := tree.Roots[2]
	if len(opensslNode.Children) != 1 {
		t.Fatalf("openssl.Children count = %d, want 1", len(opensslNode.Children))
	}
	if opensslNode.Children[0].Name != "zlib" {
		t.Errorf("openssl.Children[0].Name = %q, want zlib", opensslNode.Children[0].Name)
	}

	// zlib has no further children
	if len(opensslNode.Children[0].Children) != 0 {
		t.Errorf("zlib.Children count = %d, want 0", len(opensslNode.Children[0].Children))
	}

	// DependencyType flags
	if tree.Roots[0].DependencyType != "direct" {
		t.Errorf("boost root node DependencyType = %q, want \"direct\"", tree.Roots[0].DependencyType)
	}
	if tree.Roots[2].Children[0].DependencyType != "transitive" {
		t.Errorf("zlib child node DependencyType = %q, want \"transitive\"", tree.Roots[2].Children[0].DependencyType)
	}
}

// TestRecursiveTreeInOutput verifies that x-dependencyTree appears in the JSON output
// and has the correct recursive structure.
func TestRecursiveTreeInOutput(t *testing.T) {
	result := makeTestResult()

	tmp := filepath.Join(t.TempDir(), "sbom.json")
	if err := WriteCycloneDX(result, tmp, "1.0.0-test"); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("cannot read output file: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("cannot unmarshal CycloneDX BOM: %v", err)
	}

	// x-dependencyTree must be present with 3 roots (direct deps)
	if len(bom.DependencyTree) != 3 {
		t.Fatalf("x-dependencyTree root count = %d, want 3", len(bom.DependencyTree))
	}

	// Find openssl root
	var opensslNode *cdxTreeNode
	for _, n := range bom.DependencyTree {
		if n.Name == "openssl" {
			opensslNode = n
			break
		}
	}
	if opensslNode == nil {
		t.Fatal("openssl not found in x-dependencyTree roots")
	}

	// openssl must have zlib as a child
	if len(opensslNode.Children) != 1 {
		t.Fatalf("openssl.children count = %d, want 1", len(opensslNode.Children))
	}
	if opensslNode.Children[0].Name != "zlib" {
		t.Errorf("openssl.children[0].name = %q, want zlib", opensslNode.Children[0].Name)
	}
	if opensslNode.Children[0].Version != "1.2.13" {
		t.Errorf("zlib child version = %q, want 1.2.13", opensslNode.Children[0].Version)
	}

	// zlib child must have no further children
	if len(opensslNode.Children[0].Children) != 0 {
		t.Errorf("zlib.children count = %d, want 0", len(opensslNode.Children[0].Children))
	}
}

// TestCycloneDXProperties verifies that detection metadata is included as properties.
func TestCycloneDXProperties(t *testing.T) {
	result := makeTestResult()

	tmp := filepath.Join(t.TempDir(), "sbom.json")
	if err := WriteCycloneDX(result, tmp, "1.0.0-test"); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("cannot read output file: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("cannot unmarshal CycloneDX BOM: %v", err)
	}

	byName := map[string]cdxComponent{}
	for _, c := range bom.Components {
		byName[c.Name] = c
	}

	boost := byName["boost"]
	propMap := map[string]string{}
	for _, p := range boost.Properties {
		propMap[p.Name] = p.Value
	}

	if propMap["sbom:detectionSource"] != "conan" {
		t.Errorf("boost detectionSource = %q, want %q", propMap["sbom:detectionSource"], "conan")
	}
}

// TestCycloneDXStdout verifies that writing to "-" does not error.
func TestCycloneDXStdout(t *testing.T) {
	result := makeTestResult()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := WriteCycloneDX(result, "-", "1.0.0-test")

	w.Close()
	os.Stdout = old

	buf := make([]byte, 1<<20)
	n, _ := r.Read(buf)
	r.Close()

	if err != nil {
		t.Errorf("WriteCycloneDX to stdout failed: %v", err)
	}
	if n == 0 {
		t.Error("no output written to stdout")
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf[:n], &raw); err != nil {
		t.Errorf("stdout output is not valid JSON: %v", err)
	}
}

// TestCycloneDXSorted verifies that components are sorted alphabetically by name.
func TestCycloneDXSorted(t *testing.T) {
	result := makeTestResult()

	tmp := filepath.Join(t.TempDir(), "sbom.json")
	if err := WriteCycloneDX(result, tmp, "1.0.0-test"); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("cannot read output file: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("cannot unmarshal CycloneDX BOM: %v", err)
	}

	for i := 1; i < len(bom.Components); i++ {
		if bom.Components[i].Name < bom.Components[i-1].Name {
			t.Errorf("components not sorted: %q comes before %q",
				bom.Components[i-1].Name, bom.Components[i].Name)
		}
	}
}

// TestCycloneDXMetadata verifies the metadata block.
func TestCycloneDXMetadata(t *testing.T) {
	result := makeTestResult()

	tmp := filepath.Join(t.TempDir(), "sbom.json")
	if err := WriteCycloneDX(result, tmp, "test-version"); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("cannot read output file: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("cannot unmarshal CycloneDX BOM: %v", err)
	}

	if bom.Metadata.Timestamp == "" {
		t.Error("metadata.timestamp is empty")
	}
	if len(bom.Metadata.Tools) == 0 {
		t.Fatal("metadata.tools is empty")
	}
	tool := bom.Metadata.Tools[0]
	if tool.Name != "cpp-sbom-builder" {
		t.Errorf("tool name = %q, want %q", tool.Name, "cpp-sbom-builder")
	}
	if tool.Version != "test-version" {
		t.Errorf("tool version = %q, want %q", tool.Version, "test-version")
	}
}
