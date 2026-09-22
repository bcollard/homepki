package pki

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleIndex = "V\t270920000000Z\t\t1000\tunknown\t/O=runlocal-dev/OU=bu1/CN=gw.bu1.runlocal.dev\n" +
	"V\t270920000000Z\t\t1001\tunknown\t/O=runlocal-dev/OU=bu1/CN=other.bu1.runlocal.dev\n" +
	"R\t270920000000Z\t250101000000Z\t1002\tunknown\t/O=runlocal-dev/OU=bu1/CN=gw.bu1.runlocal.dev\n"

func writeIndex(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "index.db")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRemoveIndexEntry(t *testing.T) {
	path := writeIndex(t, sampleIndex)

	n, err := RemoveIndexEntry(path, "gw.bu1.runlocal.dev")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 {
		t.Errorf("removed %d entries, want 2", n)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "V\t270920000000Z\t\t1001\tunknown\t/O=runlocal-dev/OU=bu1/CN=other.bu1.runlocal.dev\n"
	if string(got) != want {
		t.Errorf("index.db =\n%q\nwant\n%q", got, want)
	}
}

func TestRemoveIndexEntryNoMatch(t *testing.T) {
	path := writeIndex(t, sampleIndex)

	n, err := RemoveIndexEntry(path, "absent.bu1.runlocal.dev")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("removed %d entries, want 0", n)
	}
	got, _ := os.ReadFile(path)
	if string(got) != sampleIndex {
		t.Error("index.db was modified despite no match")
	}
}

// A CN that is a suffix of another CN must not be removed by mistake.
func TestRemoveIndexEntryExactCNOnly(t *testing.T) {
	path := writeIndex(t, sampleIndex)

	n, err := RemoveIndexEntry(path, "bu1.runlocal.dev")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("removed %d entries for a partial CN, want 0", n)
	}
}

func TestRemoveIndexEntryMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.db")
	n, err := RemoveIndexEntry(path, "gw.bu1.runlocal.dev")
	if err != nil {
		t.Fatalf("missing index.db should not be an error, got: %v", err)
	}
	if n != 0 {
		t.Errorf("removed %d entries, want 0", n)
	}
}
