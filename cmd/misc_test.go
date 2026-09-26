package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListOutput(t *testing.T) {
	e := newPKIEnv(t)

	// Empty workdir and missing leaf directories are not errors.
	if out := e.mustRun("root-ca", "list"); !strings.Contains(out, "(none)") {
		t.Errorf("empty root-ca list: %q", out)
	}
	missing := filepath.Join(e.dir, "not-created")
	if out, err := execute(t, "root-ca", "list", "--workdir", missing); err != nil || !strings.Contains(out, "No Root CAs found.") {
		t.Errorf("root-ca list on a missing workdir: %q, %v", out, err)
	}
	if out, err := execute(t, "root-ca", "list", "--workdir", missing, "-o", "json"); err != nil || strings.TrimSpace(out) != "[]" {
		t.Errorf("root-ca list -o json on a missing workdir: %q, %v", out, err)
	}
	if entries := e.list("root-ca", "list"); len(entries) != 0 {
		t.Errorf("empty root-ca list JSON: %+v", entries)
	}
	if _, err := e.run("intermediate-ca", "list", "-d", "nope.test"); err == nil {
		t.Error("intermediate-ca list for a missing root: expected an error")
	}

	e.hierarchy("list.test")
	if out := e.mustRun("server-cert", "list", "-d", "list.test", "-i", "bu1"); !strings.Contains(out, "No server certificates found.") {
		t.Errorf("empty server-cert list: %q", out)
	}
	if entries := e.list("client-cert", "list", "-d", "list.test", "-i", "bu1"); len(entries) != 0 {
		t.Errorf("empty client-cert list JSON: %+v", entries)
	}

	e.mustRun("server-cert", "-d", "list.test", "-i", "bu1", "-s", "gw")
	out := e.mustRun("server-cert", "list", "-d", "list.test", "-i", "bu1")
	for _, want := range []string{"NAME", "EXPIRES", "DAYS LEFT", "CHAIN", "gw.crt", "✓ OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output lacks %q:\n%s", want, out)
		}
	}
	entries := e.list("server-cert", "list", "-d", "list.test", "-i", "bu1")
	if len(entries) != 1 || entries[0].Name != "gw.crt" || entries[0].DaysLeft < 363 || entries[0].Expires == "" {
		t.Errorf("JSON entry = %+v", entries)
	}

	// A broken certificate file shows as invalid, not as an error.
	if err := os.WriteFile(e.path("list-test", "bu1", "server-tls", "broken.crt"), []byte("junk"), 0644); err != nil {
		t.Fatal(err)
	}
	out = e.mustRun("server-cert", "list", "-d", "list.test", "-i", "bu1")
	if !strings.Contains(out, "broken.crt") || !strings.Contains(out, "✗ INVALID") || !strings.Contains(out, "unknown") {
		t.Errorf("broken certificate not reported:\n%s", out)
	}
}

func TestPrintCertTable(t *testing.T) {
	out, _ := captureStdout(t, func() error {
		printCertTable(nil)
		return nil
	})
	if !strings.Contains(out, "(none)") {
		t.Errorf("empty table: %q", out)
	}
	out, _ = captureStdout(t, func() error {
		printCertTable([]certEntry{
			{name: "a-very-long-certificate-name.crt", expiry: "2027-01-01", daysLeft: 100},
			{name: "b.crt", expiry: "unknown", daysLeft: -1, chainErr: errors.New("boom")},
		})
		return nil
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("want header, rule and 2 rows, got:\n%s", out)
	}
	if !strings.Contains(lines[3], " - ") || !strings.Contains(lines[3], "✗ INVALID: boom") {
		t.Errorf("unknown expiry row: %q", lines[3])
	}
	if strings.Index(lines[0], "EXPIRES") != strings.Index(lines[2], "2027-01-01") {
		t.Errorf("columns not aligned:\n%s", out)
	}
}

func TestPrintCertJSON(t *testing.T) {
	outputFormat = "json"
	t.Cleanup(func() { outputFormat = "table" })
	out, err := captureStdout(t, func() error {
		return printCerts([]certEntry{
			{name: "ok.crt", expiry: "2027-01-01", daysLeft: 100},
			{name: "bad.crt", expiry: "unknown", daysLeft: -1, chainErr: errors.New("boom")},
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name": "ok.crt"`, `"chain_valid": true`, `"chain_valid": false`, `"chain_error": "boom"`, `"days_left": -1`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON lacks %s:\n%s", want, out)
		}
	}
	if strings.Count(out, "chain_error") != 1 {
		t.Errorf("chain_error must be omitted for valid entries:\n%s", out)
	}
}

func TestGetEffectiveWorkDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("HOMEPKI_WORKDIR", "")
	t.Cleanup(func() { workDir = "" })

	workDir = ""
	if got, _ := getEffectiveWorkDir(); got != filepath.Join(home, ".homepki") {
		t.Errorf("default = %q", got)
	}
	t.Setenv("HOMEPKI_WORKDIR", "/from/env")
	if got, _ := getEffectiveWorkDir(); got != "/from/env" {
		t.Errorf("env = %q", got)
	}
	workDir = "/from/flag"
	if got, _ := getEffectiveWorkDir(); got != "/from/flag" {
		t.Errorf("flag = %q, want it to win over the env var", got)
	}
}

func TestHomepkiWorkdirEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOMEPKI_WORKDIR", dir)
	if _, err := execute(t, "root-ca", "-d", "env.test"); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(dir, "env-test", "ca", "env-test-root-ca.crt")) {
		t.Error("HOMEPKI_WORKDIR was not used")
	}
}

func TestVersion(t *testing.T) {
	SetVersion("1.2.3", "abc", "today")
	out, err := execute(t, "version")
	if err != nil || strings.TrimSpace(out) != "homepki 1.2.3 (abc, today)" {
		t.Errorf("version = %q, %v", out, err)
	}
}

func TestSkillCommands(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	SetSkill("---\nname: homepki\n---\nbody\n")
	dest := filepath.Join(home, ".claude", "skills", "homepki", "SKILL.md")

	if out, err := execute(t, "skill", "path"); err != nil || strings.TrimSpace(out) != dest {
		t.Errorf("skill path = %q, %v", out, err)
	}
	if out, err := execute(t, "skill", "install", "--print"); err != nil || out != skillMD {
		t.Errorf("skill install --print = %q, %v", out, err)
	}
	if exists(dest) {
		t.Fatal("--print installed the skill")
	}

	if _, err := execute(t, "skill", "install"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); string(got) != skillMD {
		t.Errorf("installed skill = %q", got)
	}

	if err := os.WriteFile(dest, []byte("stale"), 0644); err != nil {
		t.Fatal(err)
	}
	if out, _ := execute(t, "skill", "install"); !strings.Contains(out, "already installed") {
		t.Errorf("second install: %q", out)
	}
	if got, _ := os.ReadFile(dest); string(got) != "stale" {
		t.Error("install without --force overwrote the skill")
	}
	if _, err := execute(t, "skill", "install", "--force"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); string(got) != skillMD {
		t.Error("--force did not overwrite the skill")
	}
	if _, err := execute(t, "skill", "install", "--claude=false"); err == nil {
		t.Error("install with no target: expected an error")
	}
}

func TestTrustHelpers(t *testing.T) {
	if got := firstLine("one\ntwo"); got != "one" {
		t.Errorf("firstLine = %q", got)
	}
	if got := firstLine("single"); got != "single" {
		t.Errorf("firstLine = %q", got)
	}

	if got := lastLine("one\ntwo\n"); got != "two" {
		t.Errorf("lastLine = %q", got)
	}

	e := newPKIEnv(t)
	// install refuses before calling sudo when there is no root CA.
	if _, err := e.run("trust", "install", "-d", "none.test"); err == nil || !strings.Contains(err.Error(), "no Root CA certificate") {
		t.Errorf("trust install without a root: err = %v", err)
	}
	if out := e.mustRun("trust", "status"); !strings.Contains(out, "No Root CAs found.") {
		t.Errorf("trust status on an empty workdir: %q", out)
	}
	if _, err := e.run("trust", "status", "--store", "keychain"); err == nil || !strings.Contains(err.Error(), "unknown trust store") {
		t.Errorf("trust status --store keychain: err = %v", err)
	}
}

// captureStdout runs fn and returns what it printed.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	fnErr := fn()
	w.Close()
	os.Stdout = stdout
	return <-done, fnErr
}
