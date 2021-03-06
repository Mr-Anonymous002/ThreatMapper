// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package osrelease implements a featurens.Detector for container image
// layers containing an os-release file.
//
// This detector is typically useful for detecting Debian or Ubuntu.
package osrelease

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/quay/clair/v2/database"
	"github.com/quay/clair/v2/ext/featurens"
	"github.com/quay/clair/v2/ext/versionfmt/apk"
	"github.com/quay/clair/v2/ext/versionfmt/dpkg"
	"github.com/quay/clair/v2/ext/versionfmt/rpm"
	"github.com/quay/clair/v2/pkg/tarutil"
)

var (
	osReleaseOSRegexp      = regexp.MustCompile(`^ID=(.*)`)
	osReleaseVersionRegexp = regexp.MustCompile(`^VERSION_ID=(.*)`)

	// blacklistFilenames are files that should exclude this detector.
	blacklistFilenames = []string{
		"etc/oracle-release",
		"etc/redhat-release",
		"usr/lib/centos-release",
	}
)

type detector struct{}

func init() {
	featurens.RegisterDetector("os-release", &detector{})
}

func (d detector) Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	var OS, version string

	for _, filePath := range blacklistFilenames {
		if _, hasFile := files[filePath]; hasFile {
			return nil, nil
		}
	}

	for _, filePath := range d.RequiredFilenames() {
		f, hasFile := files[filePath]
		if !hasFile {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(f)))
		for scanner.Scan() {
			line := scanner.Text()

			r := osReleaseOSRegexp.FindStringSubmatch(line)
			if len(r) == 2 {
				OS = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)
			}

			r = osReleaseVersionRegexp.FindStringSubmatch(line)
			if len(r) == 2 {
				version = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)
				if OS == "alpine" {
					version = "v" + version[:strings.LastIndexByte(version, '.')]
				}
			}
		}
	}

	// Determine the VersionFormat.
	var versionFormat string
	switch OS {
	case "debian", "ubuntu":
		versionFormat = dpkg.ParserName
	case "centos", "rhel", "fedora", "amzn", "ol", "oracle":
		versionFormat = rpm.ParserName
	case "alpine":
		versionFormat = apk.ParserName
	default:
		return nil, nil
	}

	if OS != "" && version != "" {
		return &database.Namespace{
			Name:          OS + ":" + version,
			VersionFormat: versionFormat,
		}, nil
	}
	return nil, nil
}

func (d detector) RequiredFilenames() []string {
	return []string{"etc/os-release", "usr/lib/os-release"}
}
