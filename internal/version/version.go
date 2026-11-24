// Package version holds the single source of truth for the MIPAM release
// version. Import it instead of hard-coding a version string, so the CLI,
// the service status API and the packaging tool cannot drift apart.
package version

// Version is the current release version.
const Version = "0.2.0"
