// Package customize holds the cylonix-specific build-time customisation
// constants (program name, service name, etc.) used by the rebranded
// tailscale binaries.
package customize

// Customization of Tailscale settings.

const (
	ProgramName                   = "Cylonix"
	LinuxProgramName              = "cylonix"
	WindowsProgramName            = "cylonix"
	WindowsCapitalizedProgramName = "Cylonix"
	ServiceName                   = "cylonixd"
	DefaultTunnelName             = "cylonix0"
)
