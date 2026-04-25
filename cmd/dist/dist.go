// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The dist command builds Tailscale release packages for distribution.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"slices"

	"tailscale.com/release/dist"
	"tailscale.com/release/dist/cli"
	cyqnap "tailscale.com/release/dist/cylonix-qnap"       // __CYLONIX_ADD__
	cysynolo "tailscale.com/release/dist/cylonix-synology" // __CYLONIX_ADD__
	"tailscale.com/release/dist/qnap"
	"tailscale.com/release/dist/synology"
	"tailscale.com/release/dist/unixpkgs"
)

var (
	synologyPackageCenter               bool
	gcloudCredentialsBase64             string
	gcloudProject                       string
	gcloudKeyring                       string
	qnapKeyName                         string
	qnapCertificateBase64               string
	qnapCertificateIntermediariesBase64 string
	// CYLONIX_ADD: legacy private-key/certificate paths for the cylonix-qnap
	// signing flow (separate from upstream's new gcloud-based signing).
	qnapPrivateKeyPath  string
	qnapCertificatePath string
)

func getTargets() ([]dist.Target, error) {
	var ret []dist.Target

	ret = append(ret, unixpkgs.Targets(unixpkgs.Signers{})...)
	// Synology packages can be built either for sideloading, or for
	// distribution by Synology in their package center. When
	// distributed through the package center, apps can request
	// additional permissions to use a tuntap interface and control
	// the NAS's network stack, rather than be forced to run in
	// userspace mode.
	//
	// Since only we can provide packages to Synology for
	// distribution, we default to building the "sideload" variant of
	// packages that we distribute on pkgs.tailscale.com.
	//
	// To build for package center, run
	// ./tool/go run ./cmd/dist build --synology-package-center synology
	// CYLONIX_ADD: also build the cylonix-branded synology packages.
	ret = append(ret, cysynolo.Targets(synologyPackageCenter, nil)...)
	qnapSigningArgs := []string{gcloudCredentialsBase64, gcloudProject, gcloudKeyring, qnapKeyName, qnapCertificateBase64, qnapCertificateIntermediariesBase64}
	if cmp.Or(qnapSigningArgs...) != "" && slices.Contains(qnapSigningArgs, "") {
		return nil, errors.New("all of --gcloud-credentials, --gcloud-project, --gcloud-keyring, --qnap-key-name, --qnap-certificate and --qnap-certificate-intermediaries must be set")
	}
	ret = append(ret, qnap.Targets(gcloudCredentialsBase64, gcloudProject, gcloudKeyring, qnapKeyName, qnapCertificateBase64, qnapCertificateIntermediariesBase64)...)
	// CYLONIX_ADD: also build the cylonix-branded QNAP packages. The cylonix
	// QNAP target still uses the old (privateKeyPath, certificatePath) signing
	// flow rather than the new gcloud-based signing; pass --qnap-private-key-path
	// and --qnap-certificate-path on the command line to enable signing.
	// TODO(cylonix): port cyqnap to the new gcloud signing API.
	ret = append(ret, cyqnap.Targets(qnapPrivateKeyPath, qnapCertificatePath)...)
	return ret, nil
}

func main() {
	cmd := cli.CLI(getTargets)
	for _, subcmd := range cmd.Subcommands {
		if subcmd.Name == "build" {
			subcmd.FlagSet.BoolVar(&synologyPackageCenter, "synology-package-center", false, "build synology packages with extra metadata for the official package center")
			subcmd.FlagSet.StringVar(&gcloudCredentialsBase64, "gcloud-credentials", "", "base64 encoded GCP credentials (used when signing QNAP builds)")
			subcmd.FlagSet.StringVar(&gcloudProject, "gcloud-project", "", "name of project in GCP KMS (used when signing QNAP builds)")
			subcmd.FlagSet.StringVar(&gcloudKeyring, "gcloud-keyring", "", "path to keyring in GCP KMS (used when signing QNAP builds)")
			subcmd.FlagSet.StringVar(&qnapKeyName, "qnap-key-name", "", "name of GCP key to use when signing QNAP builds")
			subcmd.FlagSet.StringVar(&qnapCertificateBase64, "qnap-certificate", "", "base64 encoded certificate to use when signing QNAP builds")
			subcmd.FlagSet.StringVar(&qnapCertificateIntermediariesBase64, "qnap-certificate-intermediaries", "", "base64 encoded intermediary certificate to use when signing QNAP builds")
			// CYLONIX_ADD: legacy private-key/certificate paths for the
			// cylonix-qnap signing flow.
			subcmd.FlagSet.StringVar(&qnapPrivateKeyPath, "qnap-private-key-path", "", "path to private key to sign cylonix QNAP builds (cylonix only)")
			subcmd.FlagSet.StringVar(&qnapCertificatePath, "qnap-certificate-path", "", "path to certificate to sign cylonix QNAP builds (cylonix only)")
		}
	}

	if err := cmd.ParseAndRun(context.Background(), os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}
