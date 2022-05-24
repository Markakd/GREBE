// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package modload

import (
	"internal/testenv"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"cmd/go/internal/modfetch"
	"cmd/go/internal/modfetch/codehost"
	"cmd/go/internal/module"
)

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	dir, err := ioutil.TempDir("", "modload-test-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	modfetch.PkgMod = filepath.Join(dir, "pkg/mod")
	codehost.WorkRoot = filepath.Join(dir, "codework")
	return m.Run()
}

var (
	queryRepo   = "vcs-test.golang.org/git/querytest.git"
	queryRepoV2 = queryRepo + "/v2"
	queryRepoV3 = queryRepo + "/v3"

	// Empty version list (no semver tags), not actually empty.
	emptyRepo = "vcs-test.golang.org/git/emptytest.git"
)

var queryTests = []struct {
	path  string
	query string
	allow string
	vers  string
	err   string
}{
	/*
		git init
		echo module vcs-test.golang.org/git/querytest.git >go.mod
		git add go.mod
		git commit -m v1 go.mod
		git tag start
		for i in v0.0.0-pre1 v0.0.0 v0.0.1 v0.0.2 v0.0.3 v0.1.0 v0.1.1 v0.1.2 v0.3.0 v1.0.0 v1.1.0 v1.9.0 v1.9.9 v1.9.10-pre1; do
			echo before $i >status
			git add status
			git commit -m "before $i" status
			echo at $i >status
			git commit -m "at $i" status
			git tag $i
		done
		git tag favorite v0.0.3

		git branch v2 start
		git checkout v2
		echo module vcs-test.golang.org/git/querytest.git/v2 >go.mod
		git commit -m v2 go.mod
		for i in v2.0.0 v2.1.0 v2.2.0 v2.5.5; do
			echo before $i >status
			git add status
			git commit -m "before $i" status
			echo at $i >status
			git commit -m "at $i" status
			git tag $i
		done
		echo after v2.5.5 >status
		git commit -m 'after v2.5.5' status
		git checkout master
		zip -r ../querytest.zip
		gsutil cp ../querytest.zip gs://vcs-test/git/querytest.zip
		curl 'https://vcs-test.golang.org/git/querytest?go-get=1'
	*/
	{path: queryRepo, query: "<v0.0.0", vers: "v0.0.0-pre1"},
	{path: queryRepo, query: "<v0.0.0-pre1", err: `no matching versions for query "<v0.0.0-pre1"`},
	{path: queryRepo, query: "<=v0.0.0", vers: "v0.0.0"},
	{path: queryRepo, query: ">v0.0.0", vers: "v0.0.1"},
	{path: queryRepo, query: ">=v0.0.0", vers: "v0.0.0"},
	{path: queryRepo, query: "v0.0.1", vers: "v0.0.1"},
	{path: queryRepo, query: "v0.0.1+foo", vers: "v0.0.1"},
	{path: queryRepo, query: "v0.0.99", err: `unknown revision v0.0.99`},
	{path: queryRepo, query: "v0", vers: "v0.3.0"},
	{path: queryRepo, query: "v0.1", vers: "v0.1.2"},
	{path: queryRepo, query: "v0.2", err: `no matching versions for query "v0.2"`},
	{path: queryRepo, query: "v0.0", vers: "v0.0.3"},
	{path: queryRepo, query: "latest", vers: "v1.9.9"},
	{path: queryRepo, query: "latest", allow: "NOMATCH", err: `no matching versions for query "latest"`},
	{path: queryRepo, query: ">v1.9.9", vers: "v1.9.10-pre1"},
	{path: queryRepo, query: ">v1.10.0", err: `no matching versions for query ">v1.10.0"`},
	{path: queryRepo, query: ">=v1.10.0", err: `no matching versions for query ">=v1.10.0"`},
	{path: queryRepo, query: "6cf84eb", vers: "v0.0.2-0.20180704023347-6cf84ebaea54"},
	{path: queryRepo, query: "start", vers: "v0.0.0-20180704023101-5e9e31667ddf"},
	{path: queryRepo, query: "7a1b6bf", vers: "v0.1.0"},

	{path: queryRepoV2, query: "<v0.0.0", err: `no matching versions for query "<v0.0.0"`},
	{path: queryRepoV2, query: "<=v0.0.0", err: `no matching versions for query "<=v0.0.0"`},
	{path: queryRepoV2, query: ">v0.0.0", vers: "v2.0.0"},
	{path: queryRepoV2, query: ">=v0.0.0", vers: "v2.0.0"},
	{path: queryRepoV2, query: "v0.0.1+foo", vers: "v2.0.0-20180704023347-179bc86b1be3"},
	{path: queryRepoV2, query: "latest", vers: "v2.5.5"},

	{path: queryRepoV3, query: "latest", vers: "v3.0.0-20180704024501-e0cf3de987e6"},

	{path: emptyRepo, query: "latest", vers: "v0.0.0-20180704023549-7bb914627242"},
	{path: emptyRepo, query: ">v0.0.0", err: `no matching versions for query ">v0.0.0"`},
	{path: emptyRepo, query: "<v10.0.0", err: `no matching versions for query "<v10.0.0"`},
}

func TestQuery(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	for _, tt := range queryTests {
		allow := tt.allow
		if allow == "" {
			allow = "*"
		}
		allowed := func(m module.Version) bool {
			ok, _ := path.Match(allow, m.Version)
			return ok
		}
		t.Run(strings.ReplaceAll(tt.path, "/", "_")+"/"+tt.query+"/"+allow, func(t *testing.T) {
			info, err := Query(tt.path, tt.query, allowed)
			if tt.err != "" {
				if err != nil && err.Error() == tt.err {
					return
				}
				t.Fatalf("Query(%q, %q, %v): %v, want error %q", tt.path, tt.query, allow, err, tt.err)
			}
			if err != nil {
				t.Fatalf("Query(%q, %q, %v): %v", tt.path, tt.query, allow, err)
			}
			if info.Version != tt.vers {
				t.Errorf("Query(%q, %q, %v) = %v, want %v", tt.path, tt.query, allow, info.Version, tt.vers)
			}
		})
	}
}
