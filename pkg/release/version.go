// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package release

const (
	ID string = "v1.26.3"
)

// Version returns the release version to report. buildVersion is the value
// stamped into the binary at link time (empty when the build did not stamp
// one), in which case the ID compiled into this package is reported.
func Version(buildVersion string) string {
	if buildVersion != "" {
		return buildVersion
	}
	return ID
}
