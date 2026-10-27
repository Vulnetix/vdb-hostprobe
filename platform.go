package hostprobe

// Platform values. The order of checks in DetectPlatform matters: CI systems
// first, then orchestrators, then container runtimes, then a plain machine.
const (
	PlatformGitHub     = "github"
	PlatformGitLab     = "gitlab"
	PlatformAzure      = "azure"
	PlatformBitbucket  = "bitbucket"
	PlatformJenkins    = "jenkins"
	PlatformKubernetes = "kubernetes"
	PlatformPodman     = "podman"
	PlatformDocker     = "docker"
	PlatformMachine    = "cli"
)

// DetectPlatform says where this process runs. It reads environment variables
// that CI systems and container runtimes set, and the marker files a runtime
// leaves in the container root. The checks match the Vulnetix CLI's
// config.DetectPlatform, plus /run/.containerenv for Podman.
func DetectPlatform(s Seam) string {
	env := func(k string) string {
		if s.Getenv == nil {
			return ""
		}
		return s.Getenv(k)
	}
	exists := func(p string) bool {
		if s.Stat == nil {
			return false
		}
		_, err := s.Stat(p)
		return err == nil
	}
	switch {
	case env("GITHUB_ACTIONS") == "true" || env("GITHUB_RUN_ID") != "":
		return PlatformGitHub
	case env("GITLAB_CI") == "true" || env("CI_JOB_ID") != "":
		return PlatformGitLab
	case env("TF_BUILD") == "True" || env("AZURE_HTTP_USER_AGENT") != "" || env("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI") != "":
		return PlatformAzure
	case env("BITBUCKET_BUILD_NUMBER") != "" || env("BITBUCKET_COMMIT") != "":
		return PlatformBitbucket
	case env("JENKINS_URL") != "" || env("BUILD_NUMBER") != "":
		return PlatformJenkins
	case env("KUBERNETES_SERVICE_HOST") != "" || env("KUBERNETES_PORT") != "":
		return PlatformKubernetes
	case env("container") == "podman" || env("PODMAN_SYSTEMD_UNIT") != "" || exists("/run/.containerenv"):
		return PlatformPodman
	case exists("/.dockerenv") || env("DOCKER_CONTAINER") != "":
		return PlatformDocker
	}
	return PlatformMachine
}
