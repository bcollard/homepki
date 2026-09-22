package pki

import (
	"os"
	"strings"
)

// RemoveIndexEntry drops every row of an openssl CA database (index.db) whose
// subject DN ends with the given common name, and reports how many rows were
// removed. A missing database is not an error — there is simply nothing to
// remove. This is what makes re-issuing a leaf under an existing name possible:
// openssl refuses to sign a second certificate for a subject already listed.
func RemoveIndexEntry(indexPath, commonName string) (int, error) {
	content, err := os.ReadFile(indexPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	suffix := "/CN=" + commonName
	var kept []string
	removed := 0
	for _, line := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if strings.HasSuffix(fields[len(fields)-1], suffix) {
			removed++
			continue
		}
		kept = append(kept, line)
	}
	if removed == 0 {
		return 0, nil
	}

	out := ""
	if len(kept) > 0 {
		out = strings.Join(kept, "\n") + "\n"
	}
	if err := os.WriteFile(indexPath, []byte(out), 0644); err != nil {
		return 0, err
	}
	return removed, nil
}
