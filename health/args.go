// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package health

// Arg is a type for the key to be used in the Args of a Warnable.
type Arg string

const (
	// ArgAvailableVersion provides an update notification Warnable with the available version of the Tailscale client.
	ArgAvailableVersion Arg = "available-version"

	// ArgCurrentVersion provides an update notification Warnable with the current version of the Tailscale client.
	ArgCurrentVersion Arg = "current-version"

	// ArgDuration provides a Warnable with how long the Warnable has been in an unhealthy state.
	ArgDuration Arg = "duration"

	// ArgError provides a Warnable with the underlying error behind an unhealthy state.
	ArgError Arg = "error"

	// ArgMagicsockFunctionName provides a Warnable with the name of the Magicsock function that caused the unhealthy state.
	ArgMagicsockFunctionName Arg = "magicsock-function-name"

	// ArgDERPRegionID provides a Warnable with the ID of a DERP server involved in the unhealthy state.
	ArgDERPRegionID Arg = "derp-region-id"

	// ArgDERPRegionName provides a Warnable with the name of a DERP server involved in the unhealthy state.
	// It is used to show a more friendly message like "the Seattle relay server failed to connect" versus
	// "relay server 10 failed to connect".
	ArgDERPRegionName Arg = "derp-region-name"

	// ArgServerName provides a Warnable with the hostname of a server involved in the unhealthy state.
	ArgServerName Arg = "server-name"

	// ArgServerName provides a Warnable with comma delimited list of the hostname of the servers involved in the unhealthy state.
	// If no nameservers were available to query, this will be an empty string.
	ArgDNSServers Arg = "dns-servers"

	// __BEGIN_CYLONIX_ADD__
	// ArgTag provides a Warnable with a tag to identify the source of the
	// unhealthy state. This is used when there are multiple sources of the same
	// type of unhealthy state and we want to distinguish between them in the UI.
	ArgTag Arg = "tag"
	// __END_CYLONIX_ADD__
)
