package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/StinkyLord/cpp-sbom-builder/internal/output"
	"github.com/StinkyLord/cpp-sbom-builder/internal/scanner"
)

const toolVersion = "1.0.0"

var (
	flagDir            string
	flagOutput         string
	flagFormat         string
	flagVerbose        bool
	flagShowStrategies bool
	flagConanGraph     bool
	flagCMakeConfigure bool
	flagLdd            bool
)

var rootCmd = &cobra.Command{
	Use:   "cpp-sbom-builder",
	Short: "C++ SBOM Generation Engine",
	Long: `cpp-sbom-builder scans a C++ project directory and produces a Software
Bill of Materials (SBOM) in CycloneDX JSON format.

It uses multiple detection strategies to identify third-party dependencies:
  • compile_commands.json  — compiler-level include paths and link flags
  • Linker map files       — .map files listing every linked library
  • Build logs             — CMakeFiles/*/link.txt, MSBuild .tlog, build.ninja
  • CMake                  — CMakeCache.txt and CMakeLists.txt
  • Conan                  — conan.lock, conanfile.txt, conanfile.py
  • vcpkg                  — vcpkg.json, vcpkg-lock.json, installed/vcpkg/status
  • Meson                  — meson.build, .wrap files
  • Header scan            — #include directives (fallback)`,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a C++ project and generate an SBOM",
	Long: `Scan a C++ project directory for third-party dependencies and produce
a CycloneDX 1.4 JSON SBOM file.

Examples:
  cpp-sbom-builder scan --dir /path/to/project --output sbom.json
  cpp-sbom-builder scan --dir . --output - --verbose
  cpp-sbom-builder scan --dir /path/to/project --output sbom.json --show-strategies`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&flagDir, "dir", "d", ".", "Path to the C++ project root directory")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "sbom.json", "Output file path (use '-' for stdout)")
	scanCmd.Flags().StringVarP(&flagFormat, "format", "f", "cyclonedx", "Output format: cyclonedx")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Enable verbose output")
	scanCmd.Flags().BoolVar(&flagShowStrategies, "show-strategies", false, "Print which strategies fired after scanning")
	scanCmd.Flags().BoolVar(&flagConanGraph, "conan-graph", false,
		"Walk the project tree for conanfile.py/txt files (at any depth) and run\n"+
			"'conan graph info <dir> --format=json' for each one.\n"+
			"Conan must be on PATH (pre-installed in the cpp-sbom-builder Docker image).\n"+
			"In passive mode (without this flag) any graph.json files already present\n"+
			"in the project tree are still parsed automatically.")
	scanCmd.Flags().BoolVar(&flagCMakeConfigure, "cmake-configure", false,
		"Run cmake configure-only step to generate compile_commands.json and link.txt files.\n"+
			"Requires cmake on the host (or use inside the Docker image).\n"+
			"link.txt files are the closest equivalent to linker MAP files without a full build.")
	scanCmd.Flags().BoolVar(&flagLdd, "ldd", false,
		"Run ldd on .so files found in the project to extract runtime dependency edges.\n"+
			"Linux only. Designed to run inside the Docker image.\n"+
			"Reads ldd-results.json if pre-generated, or the SBOM_LDD_RESULTS env var.")

	rootCmd.AddCommand(scanCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(flagDir)
	if err != nil {
		return fmt.Errorf("cannot resolve directory %q: %w", flagDir, err)
	}

	info, err := os.Stat(absDir)
	if err != nil {
		return fmt.Errorf("directory %q does not exist: %w", absDir, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", absDir)
	}

	fmt.Fprintf(os.Stderr, "cpp-sbom-builder v%s\n", toolVersion)
	fmt.Fprintf(os.Stderr, "Scanning: %s\n", absDir)

	s := scanner.New(absDir, flagVerbose)
	s.ConanGraph = flagConanGraph
	s.CMakeConfigure = flagCMakeConfigure
	s.UseLdd = flagLdd
	result, err := s.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Found %d component(s)\n", len(result.Components))

	if flagShowStrategies || flagVerbose {
		if len(result.StrategiesUsed) > 0 {
			fmt.Fprintf(os.Stderr, "Strategies that found results: %v\n", result.StrategiesUsed)
		}
		if len(result.StrategiesSkipped) > 0 {
			fmt.Fprintf(os.Stderr, "Strategies with no results:    %v\n", result.StrategiesSkipped)
		}
	}

	switch flagFormat {
	case "cyclonedx", "cdx":
		if err := output.WriteCycloneDX(result, flagOutput, toolVersion); err != nil {
			return fmt.Errorf("failed to write CycloneDX output: %w", err)
		}
	default:
		return fmt.Errorf("unsupported format %q (supported: cyclonedx)", flagFormat)
	}

	if flagOutput != "-" {
		fmt.Fprintf(os.Stderr, "SBOM written to: %s\n", flagOutput)
	}

	return nil
}
