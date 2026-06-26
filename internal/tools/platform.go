package tools

import "runtime"

// Platform describes the host OS/arch plus the archive extension the
// scanners ship with. Used to build GitHub release URLs.
type Platform struct {
	OS   string // "linux", "darwin", "windows"
	Arch string // "amd64", "arm64", "386"
	Ext  string // "tar.gz" or "zip"
}

// DetectPlatform returns the current host's Platform as understood by the
// gitleaks and trivy release pipelines.
func DetectPlatform() Platform {
	p := Platform{OS: runtime.GOOS, Arch: runtime.GOARCH, Ext: "tar.gz"}
	if p.OS == "windows" {
		p.Ext = "zip"
	}
	return p
}

// GitleaksAsset returns the filename and download URL for a gitleaks release.
//
// Asset pattern: gitleaks_{ver}_{OS}_{ARCH}.{ext}
// Examples: gitleaks_8.30.1_linux_x64.tar.gz, gitleaks_8.30.1_darwin_arm64.tar.gz
//
//	gitleaks_8.30.1_windows_x64.zip
//
// Returns ok=false if the OS/arch combination isn't published.
func (p Platform) GitleaksAsset(ver string) (filename, url string, ok bool) {
	osPart, ok := map[string]string{
		"linux":   "linux",
		"darwin":  "darwin",
		"windows": "windows",
	}[p.OS]
	if !ok {
		return "", "", false
	}
	archParts, ok := gitleaksArchMatrix[p.OS]
	if !ok {
		return "", "", false
	}
	archPart, ok := archParts[p.Arch]
	if !ok {
		return "", "", false
	}
	ver = stripV(ver)
	filename = "gitleaks_" + ver + "_" + osPart + "_" + archPart + "." + p.Ext
	url = "https://github.com/gitleaks/gitleaks/releases/download/v" + ver + "/" + filename
	return filename, url, true
}

// TrivyAsset returns the filename and download URL for a trivy release.
//
// Asset pattern: trivy_{ver}_{OS}-{ARCHBITS}.{ext}
// Examples: trivy_0.71.2_Linux-64bit.tar.gz, trivy_0.71.2_macOS-ARM64.tar.gz
//
//	trivy_0.71.2_windows-64bit.zip
//
// Returns ok=false if the OS/arch combination isn't published.
func (p Platform) TrivyAsset(ver string) (filename, url string, ok bool) {
	osPart, ok := map[string]string{
		"linux":   "Linux",
		"darwin":  "macOS",
		"windows": "windows",
	}[p.OS]
	if !ok {
		return "", "", false
	}
	archParts, ok := trivyArchMatrix[p.OS]
	if !ok {
		return "", "", false
	}
	archPart, ok := archParts[p.Arch]
	if !ok {
		return "", "", false
	}
	ver = stripV(ver)
	filename = "trivy_" + ver + "_" + osPart + "-" + archPart + "." + p.Ext
	url = "https://github.com/aquasecurity/trivy/releases/download/v" + ver + "/" + filename
	return filename, url, true
}

// HadolintAsset returns the direct binary download URL for a hadolint release.
//
// Asset pattern: hadolint-{OS}-{ARCH}
// Examples: hadolint-Linux-x86_64, hadolint-Darwin-arm64,
//
//	hadolint-Windows-x86_64.exe
func (p Platform) HadolintAsset(ver string) (filename, url string, ok bool) {
	osPart, ok := map[string]string{
		"linux":   "Linux",
		"darwin":  "Darwin",
		"windows": "Windows",
	}[p.OS]
	if !ok {
		return "", "", false
	}
	archPart, ok := map[string]string{
		"amd64": "x86_64",
		"arm64": "arm64",
	}[p.Arch]
	if !ok {
		return "", "", false
	}
	suffix := ""
	if p.OS == "windows" {
		suffix = ".exe"
	}
	ver = stripV(ver)
	filename = "hadolint-" + osPart + "-" + archPart + suffix
	url = "https://github.com/hadolint/hadolint/releases/download/v" + ver + "/" + filename
	return filename, url, true
}

// GrypeAsset returns the tarball/zip filename and URL for a grype release.
//
// Asset pattern: grype_{ver}_{os}_{arch}.{ext}
// Examples: grype_0.83.0_linux_amd64.tar.gz, grype_0.83.0_windows_amd64.zip
func (p Platform) GrypeAsset(ver string) (filename, url string, ok bool) {
	osPart, ok := map[string]string{
		"linux":   "linux",
		"darwin":  "darwin",
		"windows": "windows",
	}[p.OS]
	if !ok {
		return "", "", false
	}
	archPart, ok := map[string]string{
		"amd64": "amd64",
		"arm64": "arm64",
	}[p.Arch]
	if !ok {
		return "", "", false
	}
	ver = stripV(ver)
	filename = "grype_" + ver + "_" + osPart + "_" + archPart + "." + p.Ext
	url = "https://github.com/anchore/grype/releases/download/v" + ver + "/" + filename
	return filename, url, true
}

// SyftAsset returns the tarball/zip filename and URL for a syft release.
//
// Asset pattern: syft_{ver}_{os}_{arch}.{ext}
// Examples: syft_1.45.1_linux_amd64.tar.gz, syft_1.45.1_windows_amd64.zip
func (p Platform) SyftAsset(ver string) (filename, url string, ok bool) {
	osPart, ok := map[string]string{
		"linux":   "linux",
		"darwin":  "darwin",
		"windows": "windows",
	}[p.OS]
	if !ok {
		return "", "", false
	}
	archPart, ok := map[string]string{
		"amd64": "amd64",
		"arm64": "arm64",
	}[p.Arch]
	if !ok {
		return "", "", false
	}
	ver = stripV(ver)
	filename = "syft_" + ver + "_" + osPart + "_" + archPart + "." + p.Ext
	url = "https://github.com/anchore/syft/releases/download/v" + ver + "/" + filename
	return filename, url, true
}

// OSVScannerAsset returns the direct binary download URL for osv-scanner.
//
// Asset pattern: osv-scanner_{os}_{arch}[.exe]
// Examples: osv-scanner_linux_amd64, osv-scanner_windows_amd64.exe
func (p Platform) OSVScannerAsset(ver string) (filename, url string, ok bool) {
	osPart, ok := map[string]string{
		"linux":   "linux",
		"darwin":  "darwin",
		"windows": "windows",
	}[p.OS]
	if !ok {
		return "", "", false
	}
	archPart, ok := map[string]string{
		"amd64": "amd64",
		"arm64": "arm64",
	}[p.Arch]
	if !ok {
		return "", "", false
	}
	filename = "osv-scanner_" + osPart + "_" + archPart
	if p.OS == "windows" {
		filename += ".exe"
	}
	ver = stripV(ver)
	url = "https://github.com/google/osv-scanner/releases/download/v" + ver + "/" + filename
	return filename, url, true
}

// stripV removes a leading "v" from a version tag (e.g. "v8.30.1" → "8.30.1").
func stripV(s string) string {
	if len(s) > 0 && s[0] == 'v' {
		return s[1:]
	}
	return s
}

// gitleaksArchMatrix maps "OS → arch → release asset suffix".
// Source: https://github.com/gitleaks/gitleaks/releases (verified 2026-06-22).
var gitleaksArchMatrix = map[string]map[string]string{
	"linux": {
		"amd64": "x64",
		"arm64": "arm64",
		"386":   "x32",
		"arm":   "armv6", // best-effort; gitleaks publishes armv6 and armv7
	},
	"darwin": {
		"amd64": "x64",
		"arm64": "arm64",
	},
	"windows": {
		"amd64": "x64",
		"arm64": "arm64",
		"386":   "x32",
	},
}

// trivyArchMatrix maps "OS → arch → release asset suffix".
// Source: https://github.com/aquasecurity/trivy/releases (verified 2026-06-22).
var trivyArchMatrix = map[string]map[string]string{
	"linux": {
		"amd64": "64bit",
		"arm64": "ARM64",
		"386":   "32bit",
		"arm":   "ARM",
	},
	"darwin": {
		"amd64": "64bit",
		"arm64": "ARM64",
	},
	"windows": {
		"amd64": "64bit",
		"arm64": "ARM64",
	},
}
