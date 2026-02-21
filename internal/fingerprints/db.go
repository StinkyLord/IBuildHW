// Note: idea from AI for fallback measures :D

// Package fingerprints provides a database of known C++ third-party libraries
// mapped to their characteristic include path segments and header file patterns.
// This is used as a fallback when compiler artifacts are not available.
package fingerprints

import "strings"

// LibraryFingerprint describes how to recognise a known C++ library.
type LibraryFingerprint struct {
	Name         string   // Canonical library name
	PathSegments []string // Substrings that appear in include/library paths
	Headers      []string // Characteristic header filenames or prefixes
	PURL         string   // Package URL ecosystem prefix (e.g. "pkg:conan/")
	Description  string
}

// KnownLibraries is the built-in fingerprint database.
var KnownLibraries = []LibraryFingerprint{
	{
		Name:         "boost",
		PathSegments: []string{"boost"},
		Headers:      []string{"boost/"},
		PURL:         "pkg:conan/boost",
		Description:  "Boost C++ Libraries",
	},
	{
		Name:         "openssl",
		PathSegments: []string{"openssl", "ssl", "crypto"},
		Headers:      []string{"openssl/", "ssl.h", "crypto.h"},
		PURL:         "pkg:conan/openssl",
		Description:  "OpenSSL cryptography library",
	},
	{
		Name:         "zlib",
		PathSegments: []string{"zlib"},
		Headers:      []string{"zlib.h"},
		PURL:         "pkg:conan/zlib",
		Description:  "zlib compression library",
	},
	{
		Name:         "libcurl",
		PathSegments: []string{"curl", "libcurl"},
		Headers:      []string{"curl/curl.h", "curl/"},
		PURL:         "pkg:conan/libcurl",
		Description:  "libcurl - the multiprotocol file transfer library",
	},
	{
		Name:         "sqlite3",
		PathSegments: []string{"sqlite", "sqlite3"},
		Headers:      []string{"sqlite3.h"},
		PURL:         "pkg:conan/sqlite3",
		Description:  "SQLite embedded database",
	},
	{
		Name:         "googletest",
		PathSegments: []string{"gtest", "googletest", "googlemock"},
		Headers:      []string{"gtest/gtest.h", "gmock/gmock.h"},
		PURL:         "pkg:github/google/googletest",
		Description:  "Google Test C++ testing framework",
	},
	{
		Name:         "nlohmann-json",
		PathSegments: []string{"nlohmann"},
		Headers:      []string{"nlohmann/json.hpp", "nlohmann/"},
		PURL:         "pkg:github/nlohmann/json",
		Description:  "JSON for Modern C++",
	},
	{
		Name:         "eigen",
		PathSegments: []string{"eigen", "Eigen"},
		Headers:      []string{"Eigen/", "eigen3/"},
		PURL:         "pkg:conan/eigen",
		Description:  "Eigen linear algebra library",
	},
	{
		Name:         "protobuf",
		PathSegments: []string{"protobuf", "google/protobuf"},
		Headers:      []string{"google/protobuf/", "protobuf/"},
		PURL:         "pkg:conan/protobuf",
		Description:  "Google Protocol Buffers",
	},
	{
		Name:         "grpc",
		PathSegments: []string{"grpc", "grpcpp"},
		Headers:      []string{"grpc/grpc.h", "grpcpp/"},
		PURL:         "pkg:conan/grpc",
		Description:  "gRPC remote procedure call framework",
	},
	{
		Name:         "abseil",
		PathSegments: []string{"absl", "abseil"},
		Headers:      []string{"absl/"},
		PURL:         "pkg:conan/abseil",
		Description:  "Abseil C++ Common Libraries",
	},
	{
		Name:         "fmt",
		PathSegments: []string{"fmt"},
		Headers:      []string{"fmt/format.h", "fmt/core.h", "fmt/"},
		PURL:         "pkg:conan/fmt",
		Description:  "{fmt} formatting library",
	},
	{
		Name:         "spdlog",
		PathSegments: []string{"spdlog"},
		Headers:      []string{"spdlog/spdlog.h", "spdlog/"},
		PURL:         "pkg:conan/spdlog",
		Description:  "Fast C++ logging library",
	},
	{
		Name:         "catch2",
		PathSegments: []string{"catch2", "Catch2"},
		Headers:      []string{"catch2/catch.hpp", "catch2/catch_all.hpp"},
		PURL:         "pkg:conan/catch2",
		Description:  "Catch2 C++ test framework",
	},
	{
		Name:         "libuv",
		PathSegments: []string{"libuv", "uv"},
		Headers:      []string{"uv.h", "uv/"},
		PURL:         "pkg:conan/libuv",
		Description:  "libuv asynchronous I/O library",
	},
	{
		Name:         "libpng",
		PathSegments: []string{"libpng", "png"},
		Headers:      []string{"png.h", "libpng/"},
		PURL:         "pkg:conan/libpng",
		Description:  "libpng PNG image library",
	},
	{
		Name:         "libjpeg",
		PathSegments: []string{"libjpeg", "jpeg"},
		Headers:      []string{"jpeglib.h", "jerror.h"},
		PURL:         "pkg:conan/libjpeg",
		Description:  "libjpeg JPEG image library",
	},
	{
		Name:         "opencv",
		PathSegments: []string{"opencv", "opencv2"},
		Headers:      []string{"opencv2/", "opencv/"},
		PURL:         "pkg:conan/opencv",
		Description:  "OpenCV computer vision library",
	},
	{
		Name:         "poco",
		PathSegments: []string{"Poco", "poco"},
		Headers:      []string{"Poco/"},
		PURL:         "pkg:conan/poco",
		Description:  "POCO C++ Libraries",
	},
	{
		Name:         "qt",
		PathSegments: []string{"Qt5", "Qt6", "QtCore", "QtWidgets"},
		Headers:      []string{"QtCore/", "QtWidgets/", "QtGui/", "QObject"},
		PURL:         "pkg:conan/qt",
		Description:  "Qt application framework",
	},
	{
		Name:         "wxwidgets",
		PathSegments: []string{"wx", "wxWidgets"},
		Headers:      []string{"wx/wx.h", "wx/"},
		PURL:         "pkg:conan/wxwidgets",
		Description:  "wxWidgets cross-platform GUI library",
	},
	{
		Name:         "tbb",
		PathSegments: []string{"tbb", "oneapi/tbb"},
		Headers:      []string{"tbb/tbb.h", "tbb/", "oneapi/tbb/"},
		PURL:         "pkg:conan/onetbb",
		Description:  "Intel Threading Building Blocks",
	},
	{
		Name:         "glfw",
		PathSegments: []string{"glfw", "GLFW"},
		Headers:      []string{"GLFW/glfw3.h"},
		PURL:         "pkg:conan/glfw",
		Description:  "GLFW OpenGL windowing library",
	},
	{
		Name:         "glm",
		PathSegments: []string{"glm"},
		Headers:      []string{"glm/glm.hpp", "glm/"},
		PURL:         "pkg:conan/glm",
		Description:  "OpenGL Mathematics library",
	},
	{
		Name:         "rapidjson",
		PathSegments: []string{"rapidjson"},
		Headers:      []string{"rapidjson/document.h", "rapidjson/"},
		PURL:         "pkg:conan/rapidjson",
		Description:  "RapidJSON fast JSON parser/generator",
	},
	{
		Name:         "yaml-cpp",
		PathSegments: []string{"yaml-cpp", "yaml_cpp"},
		Headers:      []string{"yaml-cpp/yaml.h"},
		PURL:         "pkg:conan/yaml-cpp",
		Description:  "yaml-cpp YAML parser",
	},
	{
		Name:         "pugixml",
		PathSegments: []string{"pugixml"},
		Headers:      []string{"pugixml.hpp"},
		PURL:         "pkg:conan/pugixml",
		Description:  "pugixml XML parser",
	},
	{
		Name:         "tinyxml2",
		PathSegments: []string{"tinyxml2"},
		Headers:      []string{"tinyxml2.h"},
		PURL:         "pkg:conan/tinyxml2",
		Description:  "TinyXML-2 XML parser",
	},
	{
		Name:         "zstd",
		PathSegments: []string{"zstd"},
		Headers:      []string{"zstd.h"},
		PURL:         "pkg:conan/zstd",
		Description:  "Zstandard compression library",
	},
	{
		Name:         "lz4",
		PathSegments: []string{"lz4"},
		Headers:      []string{"lz4.h", "lz4frame.h"},
		PURL:         "pkg:conan/lz4",
		Description:  "LZ4 compression library",
	},
	{
		Name:         "flatbuffers",
		PathSegments: []string{"flatbuffers"},
		Headers:      []string{"flatbuffers/flatbuffers.h", "flatbuffers/"},
		PURL:         "pkg:conan/flatbuffers",
		Description:  "FlatBuffers serialization library",
	},
	{
		Name:         "msgpack",
		PathSegments: []string{"msgpack"},
		Headers:      []string{"msgpack.hpp", "msgpack/"},
		PURL:         "pkg:conan/msgpack-cxx",
		Description:  "MessagePack serialization library",
	},
	{
		Name:         "asio",
		PathSegments: []string{"asio"},
		Headers:      []string{"asio.hpp", "asio/"},
		PURL:         "pkg:conan/asio",
		Description:  "Asio C++ asynchronous networking library",
	},
	{
		Name:         "websocketpp",
		PathSegments: []string{"websocketpp"},
		Headers:      []string{"websocketpp/"},
		PURL:         "pkg:conan/websocketpp",
		Description:  "WebSocket++ library",
	},
	{
		Name:         "benchmark",
		PathSegments: []string{"benchmark"},
		Headers:      []string{"benchmark/benchmark.h"},
		PURL:         "pkg:github/google/benchmark",
		Description:  "Google Benchmark microbenchmark library",
	},
	{
		Name:         "cereal",
		PathSegments: []string{"cereal"},
		Headers:      []string{"cereal/cereal.hpp", "cereal/"},
		PURL:         "pkg:conan/cereal",
		Description:  "cereal C++ serialization library",
	},
	{
		Name:         "cxxopts",
		PathSegments: []string{"cxxopts"},
		Headers:      []string{"cxxopts.hpp"},
		PURL:         "pkg:conan/cxxopts",
		Description:  "cxxopts command-line option parser",
	},
	{
		Name:         "CLI11",
		PathSegments: []string{"CLI11", "CLI"},
		Headers:      []string{"CLI/CLI.hpp"},
		PURL:         "pkg:conan/cli11",
		Description:  "CLI11 command-line parser",
	},
	{
		Name:         "re2",
		PathSegments: []string{"re2"},
		Headers:      []string{"re2/re2.h"},
		PURL:         "pkg:conan/re2",
		Description:  "RE2 regular expression library",
	},
	{
		Name:         "leveldb",
		PathSegments: []string{"leveldb"},
		Headers:      []string{"leveldb/db.h", "leveldb/"},
		PURL:         "pkg:conan/leveldb",
		Description:  "LevelDB key-value storage",
	},
	{
		Name:         "rocksdb",
		PathSegments: []string{"rocksdb"},
		Headers:      []string{"rocksdb/db.h", "rocksdb/"},
		PURL:         "pkg:conan/rocksdb",
		Description:  "RocksDB embedded database",
	},
	{
		Name:         "libsodium",
		PathSegments: []string{"sodium", "libsodium"},
		Headers:      []string{"sodium.h", "sodium/"},
		PURL:         "pkg:conan/libsodium",
		Description:  "libsodium cryptography library",
	},
	{
		Name:         "mbedtls",
		PathSegments: []string{"mbedtls"},
		Headers:      []string{"mbedtls/ssl.h", "mbedtls/"},
		PURL:         "pkg:conan/mbedtls",
		Description:  "Mbed TLS cryptography library",
	},
	{
		Name:         "libevent",
		PathSegments: []string{"libevent", "event"},
		Headers:      []string{"event2/event.h", "event.h"},
		PURL:         "pkg:conan/libevent",
		Description:  "libevent event notification library",
	},
	{
		Name:         "folly",
		PathSegments: []string{"folly"},
		Headers:      []string{"folly/"},
		PURL:         "pkg:conan/folly",
		Description:  "Facebook Open-source Library",
	},
	{
		Name:         "arrow",
		PathSegments: []string{"arrow"},
		Headers:      []string{"arrow/api.h", "arrow/"},
		PURL:         "pkg:conan/arrow",
		Description:  "Apache Arrow columnar data format",
	},
}

// stdlibHeaders is the set of standard C and C++ library headers to exclude.
var stdlibHeaders = map[string]bool{
	// C standard library
	"assert.h": true, "complex.h": true, "ctype.h": true, "errno.h": true,
	"fenv.h": true, "float.h": true, "inttypes.h": true, "iso646.h": true,
	"limits.h": true, "locale.h": true, "math.h": true, "setjmp.h": true,
	"signal.h": true, "stdalign.h": true, "stdarg.h": true, "stdatomic.h": true,
	"stdbool.h": true, "stddef.h": true, "stdint.h": true, "stdio.h": true,
	"stdlib.h": true, "stdnoreturn.h": true, "string.h": true, "tgmath.h": true,
	"threads.h": true, "time.h": true, "uchar.h": true, "wchar.h": true,
	"wctype.h": true,
	// POSIX
	"unistd.h": true, "fcntl.h": true, "sys/types.h": true, "sys/stat.h": true,
	"sys/socket.h": true, "sys/wait.h": true, "sys/mman.h": true,
	"sys/time.h": true, "sys/ioctl.h": true, "sys/select.h": true,
	"netinet/in.h": true, "arpa/inet.h": true, "netdb.h": true,
	"pthread.h": true, "semaphore.h": true, "dirent.h": true,
	"dlfcn.h": true, "poll.h": true, "termios.h": true,
	// Windows
	"windows.h": true, "winsock2.h": true, "ws2tcpip.h": true,
	"winbase.h": true, "windef.h": true, "winnt.h": true,
	"shellapi.h": true, "shlobj.h": true, "commctrl.h": true,
	// C++ standard library
	"algorithm": true, "any": true, "array": true, "atomic": true,
	"barrier": true, "bit": true, "bitset": true, "cassert": true,
	"cctype": true, "cerrno": true, "cfenv": true, "cfloat": true,
	"charconv": true, "chrono": true, "cinttypes": true, "climits": true,
	"clocale": true, "cmath": true, "codecvt": true, "compare": true,
	"complex": true, "concepts": true, "condition_variable": true,
	"coroutine": true, "csetjmp": true, "csignal": true, "cstdarg": true,
	"cstddef": true, "cstdint": true, "cstdio": true, "cstdlib": true,
	"cstring": true, "ctime": true, "cuchar": true, "cwchar": true,
	"cwctype": true, "deque": true, "exception": true, "execution": true,
	"expected": true, "filesystem": true, "format": true, "forward_list": true,
	"fstream": true, "functional": true, "future": true, "generator": true,
	"initializer_list": true, "iomanip": true, "ios": true, "iosfwd": true,
	"iostream": true, "istream": true, "iterator": true, "latch": true,
	"limits": true, "list": true, "locale": true, "map": true,
	"memory": true, "memory_resource": true, "mutex": true, "new": true,
	"numbers": true, "numeric": true, "optional": true, "ostream": true,
	"print": true, "queue": true, "random": true, "ranges": true,
	"ratio": true, "regex": true, "scoped_allocator": true, "semaphore": true,
	"set": true, "shared_mutex": true, "source_location": true, "span": true,
	"spanstream": true, "sstream": true, "stack": true, "stacktrace": true,
	"stdexcept": true, "stdfloat": true, "stop_token": true, "streambuf": true,
	"string": true, "string_view": true, "strstream": true, "syncstream": true,
	"system_error": true, "thread": true, "tuple": true, "type_traits": true,
	"typeindex": true, "typeinfo": true, "unordered_map": true,
	"unordered_set": true, "utility": true, "valarray": true, "variant": true,
	"vector": true, "version": true,
}

// IsStdlibHeader returns true if the given include name is a standard library header.
func IsStdlibHeader(include string) bool {
	// Normalise: strip leading/trailing whitespace
	include = strings.TrimSpace(include)
	return stdlibHeaders[include]
}

// MatchLibrary returns the first LibraryFingerprint whose path segments or
// headers match the given string (an include path or header name).
// Returns nil if no match is found.
func MatchLibrary(s string) *LibraryFingerprint {
	lower := strings.ToLower(s)
	for i := range KnownLibraries {
		fp := &KnownLibraries[i]
		for _, seg := range fp.PathSegments {
			if strings.Contains(lower, strings.ToLower(seg)) {
				return fp
			}
		}
		for _, hdr := range fp.Headers {
			if strings.Contains(lower, strings.ToLower(hdr)) {
				return fp
			}
		}
	}
	return nil
}
