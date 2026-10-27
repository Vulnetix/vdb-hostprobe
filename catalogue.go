package hostprobe

// Kind groups probes for display and for capability rules.
type Kind string

const (
	KindLanguage       Kind = "language"
	KindPackageManager Kind = "package-manager"
	KindToolchain      Kind = "toolchain-manager"
	KindBuild          Kind = "build"
	KindTest           Kind = "test"
	KindLint           Kind = "lint"
	KindBrowser        Kind = "browser"
	KindContainer      Kind = "container"
	KindGPU            Kind = "gpu"
	KindAI             Kind = "ai"
	KindCloud          Kind = "cloud"
	KindSCM            Kind = "scm"
	KindSecurity       Kind = "security"
	KindDatabase       Kind = "database"
	KindMedia          Kind = "media"
	KindShell          Kind = "shell"
	KindHooks          Kind = "hooks"
	KindTool           Kind = "tool"
)

// Probe is one catalogue entry: a fact name and how to find it.
type Probe struct {
	// Name is the fact name, unique, lower case: cpython, node, podman.
	Name string
	Kind Kind
	// Binaries are tried in order; the first on PATH wins.
	Binaries []string
	// Args print the version. nil means --version.
	Args []string
	// Regex extracts the version from the output. "" means the default, the
	// first dotted number. With a group, the first non-empty group is the
	// version, so a pattern can anchor on a label.
	Regex string
	// NoVersion marks a program with no safe version flag: presence only.
	NoVersion bool
	// OS limits the probe to these GOOS values. Empty means any.
	OS []string
}

func p(name string, kind Kind, bins ...string) Probe {
	return Probe{Name: name, Kind: kind, Binaries: bins}
}

func (pr Probe) args(a ...string) Probe { pr.Args = a; return pr }
func (pr Probe) re(r string) Probe      { pr.Regex = r; return pr }
func (pr Probe) bare() Probe            { pr.NoVersion = true; pr.Args = nil; return pr }
func (pr Probe) on(goos ...string) Probe {
	pr.OS = goos
	return pr
}

// catalogue is ordered by kind, then roughly by how common the tool is, so a
// sweep reports the likely facts first.
var catalogue = []Probe{
	// Language runtimes and compilers.
	p("cpython", KindLanguage, "python3", "python"),
	p("pypy", KindLanguage, "pypy3", "pypy"),
	p("micropython", KindLanguage, "micropython").args("-c", "import sys; print(sys.implementation.version)"),
	p("jython", KindLanguage, "jython"),
	p("node", KindLanguage, "node", "nodejs"),
	p("deno", KindLanguage, "deno"),
	p("bun", KindLanguage, "bun"),
	p("typescript", KindLanguage, "tsc"),
	p("go", KindLanguage, "go").args("version"),
	p("rust", KindLanguage, "rustc"),
	p("gcc", KindLanguage, "gcc"),
	p("gxx", KindLanguage, "g++"),
	p("clang", KindLanguage, "clang"),
	p("clangxx", KindLanguage, "clang++"),
	p("msvc", KindLanguage, "cl").bare().on("windows"),
	p("zig", KindLanguage, "zig").args("version"),
	p("nim", KindLanguage, "nim"),
	p("dlang", KindLanguage, "ldc2", "dmd"),
	p("odin", KindLanguage, "odin").args("version"),
	p("vlang", KindLanguage, "v").args("version"),
	p("fortran", KindLanguage, "gfortran"),
	p("ada", KindLanguage, "gnatmake"),
	p("nasm", KindLanguage, "nasm").args("-v"),
	p("java", KindLanguage, "java").args("-version").re(`version "([^"]+)"`),
	p("javac", KindLanguage, "javac").args("-version").re(`javac (\S+)`),
	p("kotlin", KindLanguage, "kotlinc").args("-version"),
	p("scala", KindLanguage, "scala-cli", "scala"),
	p("groovy", KindLanguage, "groovy"),
	p("clojure", KindLanguage, "clojure", "clj"),
	p("babashka", KindLanguage, "bb"),
	p("dotnet", KindLanguage, "dotnet"),
	p("mono", KindLanguage, "mono"),
	p("powershell", KindLanguage, "pwsh"),
	p("ruby", KindLanguage, "ruby"),
	p("jruby", KindLanguage, "jruby"),
	p("truffleruby", KindLanguage, "truffleruby"),
	p("php", KindLanguage, "php"),
	p("perl", KindLanguage, "perl"),
	p("lua", KindLanguage, "lua", "lua5.4", "lua5.3").args("-v"),
	p("luajit", KindLanguage, "luajit").args("-v"),
	p("r", KindLanguage, "Rscript"),
	p("julia", KindLanguage, "julia"),
	p("erlang", KindLanguage, "erl").args("-noshell", "-eval", `io:fwrite("~s~n",[erlang:system_info(otp_release)]),halt().`).re(`\d+`),
	p("elixir", KindLanguage, "elixir").re(`Elixir (\d+\.\d+(?:\.\d+)?)`),
	p("gleam", KindLanguage, "gleam"),
	p("haskell", KindLanguage, "ghc"),
	p("ocaml", KindLanguage, "ocaml").args("-version"),
	p("racket", KindLanguage, "racket"),
	p("common-lisp", KindLanguage, "sbcl"),
	p("guile", KindLanguage, "guile"),
	p("chez-scheme", KindLanguage, "chezscheme", "chez", "scheme"),
	p("elm", KindLanguage, "elm"),
	p("purescript", KindLanguage, "purs"),
	p("swift", KindLanguage, "swift"),
	p("dart", KindLanguage, "dart"),
	p("flutter", KindLanguage, "flutter").bare(), // its --version can run first-run setup and a network check
	p("solidity", KindLanguage, "solc"),
	p("emscripten", KindLanguage, "emcc"),
	p("wasmtime", KindLanguage, "wasmtime"),
	p("wasmer", KindLanguage, "wasmer"),
	p("wasm-pack", KindBuild, "wasm-pack"),

	// System package managers.
	p("apt", KindPackageManager, "apt-get", "apt").on("linux"),
	p("aptitude", KindPackageManager, "aptitude").on("linux"),
	p("dpkg", KindPackageManager, "dpkg").on("linux"),
	p("dnf", KindPackageManager, "dnf").on("linux"),
	p("yum", KindPackageManager, "yum").on("linux"),
	p("microdnf", KindPackageManager, "microdnf").on("linux"),
	p("rpm-ostree", KindPackageManager, "rpm-ostree").on("linux"),
	p("rpm", KindPackageManager, "rpm").on("linux"),
	p("zypper", KindPackageManager, "zypper").on("linux"),
	p("apk", KindPackageManager, "apk").on("linux"),
	p("pacman", KindPackageManager, "pacman").on("linux"),
	p("yay", KindPackageManager, "yay").on("linux"),
	p("paru", KindPackageManager, "paru").on("linux"),
	p("emerge", KindPackageManager, "emerge").on("linux"),
	p("xbps", KindPackageManager, "xbps-install").args("-V").on("linux"),
	p("eopkg", KindPackageManager, "eopkg").on("linux"),
	p("nix", KindPackageManager, "nix"),
	p("guix", KindPackageManager, "guix").on("linux"),
	p("snap", KindPackageManager, "snap").args("version").on("linux"),
	p("flatpak", KindPackageManager, "flatpak").on("linux"),
	p("brew", KindPackageManager, "brew").on("darwin", "linux"),
	p("macports", KindPackageManager, "port").args("version").on("darwin"),
	p("pkgin", KindPackageManager, "pkgin").args("-v"),
	p("freebsd-pkg", KindPackageManager, "pkg").args("-v").on("freebsd"),
	p("openbsd-pkg", KindPackageManager, "pkg_add").bare().on("openbsd"),
	p("choco", KindPackageManager, "choco").on("windows"),
	p("scoop", KindPackageManager, "scoop").on("windows"),
	p("winget", KindPackageManager, "winget").on("windows"),

	// Toolchain and version managers.
	p("mise", KindToolchain, "mise"),
	p("asdf", KindToolchain, "asdf").args("version"),
	p("rustup", KindToolchain, "rustup"),
	p("pyenv", KindToolchain, "pyenv"),
	p("conda", KindToolchain, "conda"),
	p("mamba", KindToolchain, "mamba"),
	p("micromamba", KindToolchain, "micromamba"),
	p("fnm", KindToolchain, "fnm"),
	p("volta", KindToolchain, "volta"),
	p("corepack", KindToolchain, "corepack"),
	p("ghcup", KindToolchain, "ghcup").args("--numeric-version"),

	// Language package managers. The names match the CLI's autofix binaries.
	p("npm", KindPackageManager, "npm"),
	p("pnpm", KindPackageManager, "pnpm"),
	p("yarn", KindPackageManager, "yarn"),
	p("pip", KindPackageManager, "pip3", "pip"),
	p("pipx", KindPackageManager, "pipx"),
	p("uv", KindPackageManager, "uv"),
	p("poetry", KindPackageManager, "poetry"),
	p("pdm", KindPackageManager, "pdm"),
	p("hatch", KindPackageManager, "hatch"),
	p("pipenv", KindPackageManager, "pipenv"),
	p("gem", KindPackageManager, "gem"),
	p("bundler", KindPackageManager, "bundle"),
	p("composer", KindPackageManager, "composer"),
	p("cargo", KindPackageManager, "cargo"),
	p("maven", KindPackageManager, "mvn").args("-v"),
	p("gradle", KindPackageManager, "gradle"),
	p("leiningen", KindPackageManager, "lein").bare(), // the first run downloads Leiningen itself
	p("sbt", KindPackageManager, "sbt").args("--script-version"),
	p("nuget", KindPackageManager, "nuget").args("help"),
	p("cpanm", KindPackageManager, "cpanm"),
	p("luarocks", KindPackageManager, "luarocks"),
	p("cabal", KindPackageManager, "cabal"),
	p("stack", KindPackageManager, "stack"),
	p("opam", KindPackageManager, "opam"),
	p("rebar3", KindPackageManager, "rebar3").args("version"),
	p("conan", KindPackageManager, "conan"),
	p("vcpkg", KindPackageManager, "vcpkg").args("version"),
	p("cocoapods", KindPackageManager, "pod").on("darwin"),
	p("carthage", KindPackageManager, "carthage").args("version").on("darwin"),

	// Build tools.
	p("make", KindBuild, "make", "gmake"),
	p("cmake", KindBuild, "cmake"),
	p("ninja", KindBuild, "ninja"),
	p("meson", KindBuild, "meson"),
	p("bazel", KindBuild, "bazelisk", "bazel"),
	p("buck2", KindBuild, "buck2"),
	p("just", KindBuild, "just"),
	p("task", KindBuild, "task"),
	p("pkg-config", KindBuild, "pkg-config", "pkgconf"),
	p("autoconf", KindBuild, "autoconf"),
	p("ant", KindBuild, "ant").args("-version"),
	p("msbuild", KindBuild, "msbuild").args("-version"),
	p("xcodebuild", KindBuild, "xcodebuild").args("-version").on("darwin"),
	p("xcrun-simctl", KindBuild, "xcrun").bare().on("darwin"),
	p("android-sdkmanager", KindBuild, "sdkmanager"),
	p("adb", KindBuild, "adb").args("version"),
	p("android-emulator", KindBuild, "emulator").args("-version"),
	p("goreleaser", KindBuild, "goreleaser").args("--version"),

	// Test runners and harnesses.
	p("pytest", KindTest, "pytest"),
	p("jest", KindTest, "jest"),
	p("vitest", KindTest, "vitest"),
	p("mocha", KindTest, "mocha"),
	p("playwright", KindTest, "playwright"),
	p("cypress", KindTest, "cypress").args("version"),
	p("webdriverio", KindTest, "wdio"),
	p("testcafe", KindTest, "testcafe"),
	p("appium", KindTest, "appium"),
	p("detox", KindTest, "detox"),
	p("k6", KindTest, "k6").args("version"),
	p("locust", KindTest, "locust"),
	p("jmeter", KindTest, "jmeter").args("-v"),
	p("gatling", KindTest, "gatling.sh", "gatling").bare(),
	p("artillery", KindTest, "artillery"),
	p("wrk", KindTest, "wrk").args("-v"),
	p("hey", KindTest, "hey").bare(),
	p("vegeta", KindTest, "vegeta").args("-version"),
	p("hyperfine", KindTest, "hyperfine"),
	p("apache-bench", KindTest, "ab").args("-V"),
	p("afl", KindTest, "afl-fuzz").bare(),
	p("honggfuzz", KindTest, "honggfuzz").bare(),
	p("cargo-fuzz", KindTest, "cargo-fuzz"),
	p("stryker", KindTest, "stryker"),
	p("mutmut", KindTest, "mutmut"),
	p("cargo-mutants", KindTest, "cargo-mutants"),
	p("newman", KindTest, "newman"),
	p("schemathesis", KindTest, "st", "schemathesis"),
	p("dredd", KindTest, "dredd"),
	p("pact", KindTest, "pact-broker", "pact").bare(),
	p("pa11y", KindTest, "pa11y"),
	p("lighthouse-ci", KindTest, "lhci"),
	p("axe", KindTest, "axe"),
	p("backstop", KindTest, "backstop").args("version"),
	p("chromedriver", KindTest, "chromedriver"),
	p("geckodriver", KindTest, "geckodriver"),

	// Linters and formatters.
	p("ruff", KindLint, "ruff"),
	p("golangci-lint", KindLint, "golangci-lint"),
	p("eslint", KindLint, "eslint"),
	p("prettier", KindLint, "prettier"),
	p("rubocop", KindLint, "rubocop"),
	p("shellcheck", KindLint, "shellcheck"),
	p("hadolint", KindLint, "hadolint"),
	p("actionlint", KindLint, "actionlint"),

	// Browsers.
	p("chrome", KindBrowser, "google-chrome", "google-chrome-stable", "chrome"),
	p("chromium", KindBrowser, "chromium", "chromium-browser", "chromium-headless-shell"),
	p("firefox", KindBrowser, "firefox"),

	// Containers, virtualisation and isolation.
	p("podman", KindContainer, "podman"),
	p("docker", KindContainer, "docker"),
	p("buildah", KindContainer, "buildah"),
	p("nerdctl", KindContainer, "nerdctl"),
	p("compose", KindContainer, "podman-compose", "docker-compose").re(`(?i)compose version v?(\d+\.\d+(?:\.\d+)?)`),
	p("skopeo", KindContainer, "skopeo"),
	p("crane", KindContainer, "crane").args("version"),
	p("kubectl", KindContainer, "kubectl").args("version", "--client"),
	p("helm", KindContainer, "helm").args("version", "--short"),
	p("kind", KindContainer, "kind").args("version"),
	p("k3d", KindContainer, "k3d").args("version"),
	p("minikube", KindContainer, "minikube").args("version", "--short"),
	p("bubblewrap", KindContainer, "bwrap").on("linux"),
	p("qemu", KindContainer, "qemu-system-x86_64", "qemu-system-aarch64"),
	p("firecracker", KindContainer, "firecracker").on("linux"),

	// GPUs and local AI.
	p("nvidia-smi", KindGPU, "nvidia-smi").args("--query-gpu=driver_version", "--format=csv,noheader"),
	p("rocm-smi", KindGPU, "rocm-smi").args("--showdriverversion"),
	p("ollama", KindAI, "ollama"),
	p("llama-cpp", KindAI, "llama-server", "llama-cli"),
	p("vllm", KindAI, "vllm"),
	p("lm-studio", KindAI, "lms").args("version"),
	p("localai", KindAI, "local-ai"),
	p("tgi", KindAI, "text-generation-launcher"),
	p("koboldcpp", KindAI, "koboldcpp"),
	p("whisper-cpp", KindAI, "whisper-cli", "whisper-cpp").bare(),
	p("litellm", KindAI, "litellm"),
	p("tensorrt", KindAI, "trtexec").bare(),

	// Cloud and infrastructure CLIs. Presence and version only; sign-in state
	// is the caller's concern.
	p("aws", KindCloud, "aws"),
	p("azure-cli", KindCloud, "az").bare(), // az --version checks for updates online
	p("gcloud", KindCloud, "gcloud"),
	p("terraform", KindCloud, "terraform").args("version"),
	p("opentofu", KindCloud, "tofu").args("version"),
	p("pulumi", KindCloud, "pulumi").args("version"),
	p("eksctl", KindCloud, "eksctl").args("version"),
	p("flyctl", KindCloud, "flyctl", "fly").args("version"),
	p("doctl", KindCloud, "doctl").args("version"),
	p("heroku", KindCloud, "heroku").bare(), // the CLI may auto-update on any command
	p("vercel", KindCloud, "vercel").bare(),
	p("netlify", KindCloud, "netlify").bare(),
	p("linode-cli", KindCloud, "linode-cli"),
	p("wrangler", KindCloud, "wrangler"),

	// Source control.
	p("git", KindSCM, "git"),
	p("git-lfs", KindSCM, "git-lfs"),
	p("gh", KindSCM, "gh"),
	p("glab", KindSCM, "glab"),
	p("mercurial", KindSCM, "hg"),
	p("subversion", KindSCM, "svn"),

	// Git hook managers.
	p("pre-commit", KindHooks, "pre-commit"),
	p("lefthook", KindHooks, "lefthook").args("version"),
	p("overcommit", KindHooks, "overcommit"),

	// Security tools.
	p("vulnetix", KindSecurity, "vulnetix").args("version"),
	p("semgrep", KindSecurity, "semgrep").args("--version", "--disable-version-check"),
	p("gitleaks", KindSecurity, "gitleaks").args("version"),
	p("trufflehog", KindSecurity, "trufflehog"),
	p("syft", KindSecurity, "syft").args("version"),
	p("grype", KindSecurity, "grype").args("version"),
	p("trivy", KindSecurity, "trivy"),
	p("osv-scanner", KindSecurity, "osv-scanner"),
	p("cdxgen", KindSecurity, "cdxgen"),
	p("cosign", KindSecurity, "cosign").args("version"),
	p("gpg", KindSecurity, "gpg"),
	p("checkov", KindSecurity, "checkov"),
	p("yara", KindSecurity, "yara"),
	p("radare2", KindSecurity, "r2", "radare2").args("-v"),
	p("binwalk", KindSecurity, "binwalk").bare(),
	p("ghidra", KindSecurity, "analyzeHeadless").bare(),
	p("nuclei", KindSecurity, "nuclei").bare(), // checks for template updates on start
	p("zap", KindSecurity, "zap.sh", "zaproxy").bare(),
	p("sqlmap", KindSecurity, "sqlmap"),
	p("nikto", KindSecurity, "nikto").args("-Version"),
	p("tcpdump", KindSecurity, "tcpdump"),
	p("mitmproxy", KindSecurity, "mitmdump"),
	p("snort", KindSecurity, "snort").args("-V"),
	p("suricata", KindSecurity, "suricata").args("-V"),

	// Databases for integration tests.
	p("postgres-client", KindDatabase, "psql"),
	p("postgres", KindDatabase, "postgres"),
	p("mysql-client", KindDatabase, "mysql"),
	p("mysql", KindDatabase, "mysqld"),
	p("redis", KindDatabase, "redis-server"),
	p("sqlite", KindDatabase, "sqlite3").args("-version"),
	p("duckdb", KindDatabase, "duckdb").args("-version"),
	p("mongodb", KindDatabase, "mongod"),

	// Media and documents.
	p("ffmpeg", KindMedia, "ffmpeg").args("-version"),
	p("imagemagick", KindMedia, "magick", "convert"),
	p("pandoc", KindMedia, "pandoc"),
	p("latex", KindMedia, "tectonic", "pdflatex"),
	p("wkhtmltopdf", KindMedia, "wkhtmltopdf"),

	// Shells.
	p("bash", KindShell, "bash"),
	p("zsh", KindShell, "zsh"),
	p("fish", KindShell, "fish"),

	// General tools agents lean on.
	p("jq", KindTool, "jq"),
	p("yq", KindTool, "yq"),
	p("ripgrep", KindTool, "rg"),
	p("fd", KindTool, "fd", "fdfind"),
	p("curl", KindTool, "curl"),
	p("wget", KindTool, "wget"),
}

// Catalogue returns a copy of every probe, in sweep order.
func Catalogue() []Probe {
	out := make([]Probe, len(catalogue))
	copy(out, catalogue)
	return out
}

// Lookup returns the probe with this name.
func Lookup(name string) (Probe, bool) {
	for _, pr := range catalogue {
		if pr.Name == name {
			return pr, true
		}
	}
	return Probe{}, false
}

// For returns the probes that apply to goos.
func For(goos string) []Probe {
	out := make([]Probe, 0, len(catalogue))
	for _, pr := range catalogue {
		if pr.applies(goos) {
			out = append(out, pr)
		}
	}
	return out
}

func (pr Probe) applies(goos string) bool {
	if len(pr.OS) == 0 {
		return true
	}
	for _, o := range pr.OS {
		if o == goos {
			return true
		}
	}
	return false
}
