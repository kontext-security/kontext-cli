package judge

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBuildLlamaServerArgsUsesLocalModel(t *testing.T) {
	got := BuildLlamaServerArgs(LlamaServerOptions{
		ModelPath: "/models/qwen.gguf",
		Host:      "127.0.0.1",
		Port:      18081,
	})
	want := []string{"--model", "/models/qwen.gguf", "--host", "127.0.0.1", "--port", "18081"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestStartLlamaServerMissingBinary(t *testing.T) {
	modelPath := writeTestModel(t)
	_, err := StartLlamaServer(context.Background(), LlamaServerOptions{
		BinaryPath: "kontext-missing-llama-server",
		ModelPath:  modelPath,
	})
	if err == nil {
		t.Fatal("StartLlamaServer() error = nil, want missing binary error")
	}
	if !strings.Contains(err.Error(), "find kontext-missing-llama-server") {
		t.Fatalf("err = %v, want missing binary", err)
	}
}

func TestStartLlamaServerMissingBinaryDoesNotDownloadModel(t *testing.T) {
	downloaded := false
	_, err := StartLlamaServer(context.Background(), LlamaServerOptions{
		BinaryPath: "kontext-missing-llama-server",
		CacheDir:   t.TempDir(),
		HFRepo:     "Qwen/Qwen3-0.6B-GGUF",
		HFFile:     "Qwen3-0.6B-Q8_0.gguf",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			downloaded = true
			return http.DefaultTransport.RoundTrip(req)
		})},
	})
	if err == nil {
		t.Fatal("StartLlamaServer() error = nil, want missing binary error")
	}
	if downloaded {
		t.Fatal("model download started before checking llama-server binary")
	}
}

func TestStartLlamaServerRejectsOccupiedPort(t *testing.T) {
	modelPath := writeTestModel(t)
	binaryPath := writeFakeLlamaServer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	_, err = StartLlamaServer(context.Background(), LlamaServerOptions{
		BinaryPath: binaryPath,
		ModelPath:  modelPath,
		Port:       port,
	})
	if err == nil {
		t.Fatal("StartLlamaServer() error = nil, want occupied port rejection")
	}
	if !strings.Contains(err.Error(), "llama-server port 127.0.0.1:") {
		t.Fatalf("err = %v, want occupied port error", err)
	}
}

func TestStartLlamaServerHealthCheckAndStop(t *testing.T) {
	modelPath := writeTestModel(t)
	binaryPath := writeFakeLlamaServer(t)
	port := freeTCPPort(t)
	server, err := StartLlamaServer(context.Background(), LlamaServerOptions{
		BinaryPath:     binaryPath,
		ModelPath:      modelPath,
		Port:           port,
		StartupTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.BaseURL() != "http://127.0.0.1:"+strconv.Itoa(port) {
		t.Fatalf("BaseURL() = %q", server.BaseURL())
	}
	if err := server.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestStartLlamaServerEarlyExitDoesNotWaitForStopTimeout(t *testing.T) {
	modelPath := writeTestModel(t)
	binaryPath := writeFakeExitingLlamaServer(t)
	startupTimeout := 2 * time.Second
	start := time.Now()
	_, err := StartLlamaServer(context.Background(), LlamaServerOptions{
		BinaryPath:     binaryPath,
		ModelPath:      modelPath,
		Port:           freeTCPPort(t),
		StartupTimeout: startupTimeout,
	})
	if err == nil {
		t.Fatal("StartLlamaServer() error = nil, want early exit error")
	}
	if elapsed := time.Since(start); elapsed > startupTimeout {
		t.Fatalf("early exit took %s, want less than %s", elapsed, startupTimeout)
	}
}

func TestCachedHFModelPathRejectsTraversal(t *testing.T) {
	if _, err := CachedHFModelPath(t.TempDir(), "Qwen/Qwen3-0.6B-GGUF", "main", "../model.gguf"); err == nil {
		t.Fatal("CachedHFModelPath() error = nil, want traversal rejection")
	}
}

func TestCachedHFModelPathIncludesRevision(t *testing.T) {
	got, err := CachedHFModelPath("/cache", "Qwen/Qwen3-0.6B-GGUF", "refs/pr/1", "Qwen3-0.6B-Q8_0.gguf")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/cache", "huggingface", "Qwen", "Qwen3-0.6B-GGUF", "refs/pr/1", "Qwen3-0.6B-Q8_0.gguf")
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestResolveLlamaServerModelUsesCachedFile(t *testing.T) {
	cacheDir := t.TempDir()
	want, err := CachedHFModelPath(cacheDir, "Qwen/Qwen3-0.6B-GGUF", "main", "Qwen3-0.6B-Q8_0.gguf")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("gguf"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveLlamaServerModel(context.Background(), LlamaServerOptions{
		CacheDir: cacheDir,
		HFRepo:   "Qwen/Qwen3-0.6B-GGUF",
		HFFile:   "Qwen3-0.6B-Q8_0.gguf",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("model path = %q, want %q", got, want)
	}
}

func TestResolveLlamaServerModelDownloadsToCache(t *testing.T) {
	cacheDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Qwen/Qwen3-0.6B-GGUF/resolve/main/Qwen3-0.6B-Q8_0.gguf" {
			t.Fatalf("download path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte("gguf"))
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ResolveLlamaServerModel(context.Background(), LlamaServerOptions{
		CacheDir:   cacheDir,
		HFRepo:     "Qwen/Qwen3-0.6B-GGUF",
		HFFile:     "Qwen3-0.6B-Q8_0.gguf",
		HFRevision: "main",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rewritten := req.Clone(req.Context())
			rewritten.URL.Scheme = target.Scheme
			rewritten.URL.Host = target.Host
			return http.DefaultTransport.RoundTrip(rewritten)
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes) != "gguf" {
		t.Fatalf("cached bytes = %q, want gguf", bytes)
	}
}

func TestResolveLlamaServerModelDownloadsCustomRevision(t *testing.T) {
	cacheDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Qwen/Qwen3-0.6B-GGUF/resolve/refs/pr/1/Qwen3-0.6B-Q8_0.gguf" {
			t.Fatalf("download path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte("gguf"))
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ResolveLlamaServerModel(context.Background(), LlamaServerOptions{
		CacheDir:   cacheDir,
		HFRepo:     "Qwen/Qwen3-0.6B-GGUF",
		HFFile:     "Qwen3-0.6B-Q8_0.gguf",
		HFRevision: "refs/pr/1",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rewritten := req.Clone(req.Context())
			rewritten.URL.Scheme = target.Scheme
			rewritten.URL.Host = target.Host
			return http.DefaultTransport.RoundTrip(rewritten)
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, filepath.Join("Qwen3-0.6B-GGUF", "refs/pr/1", "Qwen3-0.6B-Q8_0.gguf")) {
		t.Fatalf("cached path = %q, want revision included", got)
	}
}

func TestUnavailableJudgeFailsWithMetadata(t *testing.T) {
	localJudge := UnavailableJudge{Runtime: DefaultLlamaServerRuntime, Model: "qwen", Err: os.ErrNotExist}
	_, err := localJudge.Decide(context.Background(), Input{HookEvent: "PreToolUse"})
	if FailureKind(err) != FailureUnavailable {
		t.Fatalf("FailureKind(err) = %q, want unavailable", FailureKind(err))
	}
	if metadata := localJudge.Metadata(); metadata.Runtime != DefaultLlamaServerRuntime || metadata.Model != "qwen" {
		t.Fatalf("metadata = %+v", metadata)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestFakeLlamaServerProcess(t *testing.T) {
	if os.Getenv("KONTEXT_FAKE_LLAMA_SERVER") != "1" {
		return
	}
	args := os.Args
	port := ""
	for i, arg := range args {
		if arg == "--" && i+1 < len(args) {
			port = args[i+1]
			break
		}
	}
	if port == "" {
		os.Exit(2)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"fake"}]}`))
	})
	if err := http.ListenAndServe("127.0.0.1:"+port, mux); err != nil {
		os.Exit(1)
	}
}

func writeTestModel(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "model.gguf")
	if err := os.WriteFile(path, []byte("gguf"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFakeLlamaServer(t *testing.T) string {
	t.Helper()
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "llama-server")
	script := `#!/bin/sh
port=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--port" ]; then
    shift
    port="$1"
  fi
  shift
done
KONTEXT_FAKE_LLAMA_SERVER=1 exec ` + shellQuote(testBinary) + ` -test.run=TestFakeLlamaServerProcess -- "$port"
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFakeExitingLlamaServer(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "llama-server")
	script := "#!/bin/sh\nexit 42\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
