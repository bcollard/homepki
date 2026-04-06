package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	ansiRed   = "\033[31m"
	ansiGreen = "\033[32m"
	ansiReset = "\033[0m"
)

var outputFormat string

type certEntry struct {
	name     string
	expiry   string // ISO date or "unknown"
	daysLeft int    // -1 if unknown
	chainErr error
}

func printCertTable(entries []certEntry) {
	if len(entries) == 0 {
		fmt.Println("  (none)")
		return
	}

	nameW := len("NAME")
	expiryW := len("EXPIRES")
	daysW := len("DAYS LEFT")
	for _, e := range entries {
		if len(e.name) > nameW {
			nameW = len(e.name)
		}
		if len(e.expiry) > expiryW {
			expiryW = len(e.expiry)
		}
		d := fmt.Sprintf("%d", e.daysLeft)
		if e.daysLeft < 0 {
			d = "-"
		}
		if len(d) > daysW {
			daysW = len(d)
		}
	}

	fmt.Printf("  %-*s  %-*s  %-*s  %s\n",
		nameW, "NAME",
		expiryW, "EXPIRES",
		daysW, "DAYS LEFT",
		"CHAIN",
	)
	fmt.Printf("  %s  %s  %s  %s\n",
		strings.Repeat("─", nameW),
		strings.Repeat("─", expiryW),
		strings.Repeat("─", daysW),
		strings.Repeat("─", 10),
	)

	for _, e := range entries {
		daysStr := fmt.Sprintf("%d", e.daysLeft)
		if e.daysLeft < 0 {
			daysStr = "-"
		}
		var chainStr string
		if e.chainErr != nil {
			chainStr = ansiRed + "✗ INVALID: " + e.chainErr.Error() + ansiReset
		} else {
			chainStr = ansiGreen + "✓ OK" + ansiReset
		}
		fmt.Printf("  %-*s  %-*s  %-*s  %s\n",
			nameW, e.name,
			expiryW, e.expiry,
			daysW, daysStr,
			chainStr,
		)
	}
}

func printCertJSON(entries []certEntry) error {
	type jsonEntry struct {
		Name       string `json:"name"`
		Expires    string `json:"expires"`
		DaysLeft   int    `json:"days_left"`
		ChainValid bool   `json:"chain_valid"`
		ChainError string `json:"chain_error,omitempty"`
	}
	out := make([]jsonEntry, len(entries))
	for i, e := range entries {
		je := jsonEntry{
			Name:       e.name,
			Expires:    e.expiry,
			DaysLeft:   e.daysLeft,
			ChainValid: e.chainErr == nil,
		}
		if e.chainErr != nil {
			je.ChainError = e.chainErr.Error()
		}
		out[i] = je
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func printCerts(entries []certEntry) error {
	switch outputFormat {
	case "json":
		return printCertJSON(entries)
	default:
		printCertTable(entries)
		return nil
	}
}
