package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bcollard/homepki/pkg/pki"
	"github.com/spf13/cobra"
)

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Add a Root CA to the macOS system trust store",
	Long: `Manage the macOS system trust store for a homepki Root CA.

Installing the Root CA makes every certificate under it trusted by the
applications that read the system keychain — Safari, Chrome, curl, and anything
built on Secure Transport. Firefox and Java keep their own trust stores and are
not covered.

Servers must still present the intermediate: serve the leaf with
<intermediate>-intermediate-ca-chain.crt, or clients cannot build the path to
the trusted root.

These commands are macOS-only. Installing into the system keychain requires
root, so homepki re-runs itself under sudo, which may prompt for your password.`,
}

var trustInstallCmd = &cobra.Command{
	Use:     "install",
	Short:   "Trust a Root CA system-wide (writes to the System keychain, needs sudo)",
	Example: `  homepki trust install --domain runlocal.dev`,
	RunE: func(cmd *cobra.Command, args []string) error {
		certPath, err := trustCertPath()
		if err != nil {
			return err
		}

		fmt.Printf("Adding %s to the macOS system keychain.\n", certPath)
		fmt.Println("sudo may ask for your password.")
		if err := pki.RunInteractive(pki.Sudo(pki.MacOSTrustInstallArgs(certPath))); err != nil {
			return fmt.Errorf("adding the Root CA to the system keychain: %w", err)
		}

		if _, err := pki.RunQuiet(pki.MacOSTrustStatusArgs(certPath)); err != nil {
			return fmt.Errorf("the Root CA was added but still does not verify as trusted: %w", err)
		}
		fmt.Printf("Root CA for %s is now trusted system-wide.\n", rootCADomain)
		fmt.Println("Firefox and Java keep separate trust stores and are unaffected.")
		fmt.Println("Serve leaves with the intermediate chain file so clients can reach this root.")
		return nil
	},
}

var trustUninstallCmd = &cobra.Command{
	Use:     "uninstall",
	Short:   "Stop trusting a Root CA system-wide (needs sudo)",
	Example: `  homepki trust uninstall --domain runlocal.dev`,
	RunE: func(cmd *cobra.Command, args []string) error {
		certPath, err := trustCertPath()
		if err != nil {
			return err
		}

		fmt.Printf("Removing the trust setting for %s.\n", certPath)
		fmt.Println("sudo may ask for your password.")
		if err := pki.RunInteractive(pki.Sudo(pki.MacOSTrustUninstallArgs(certPath))); err != nil {
			return fmt.Errorf("removing the Root CA trust setting: %w", err)
		}

		fmt.Printf("Root CA for %s is no longer trusted.\n", rootCADomain)
		fmt.Println("The certificate itself may remain in the keychain; remove it with Keychain Access if you want it gone.")
		return nil
	},
}

var trustStatusCmd = &cobra.Command{
	Use:     "status",
	Aliases: []string{"st"},
	Short:   "Report whether a Root CA is trusted by this Mac",
	Example: `  homepki trust status
  homepki trust status --domain runlocal.dev
  homepki trust status -o json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireMacOS(); err != nil {
			return err
		}

		var domains []string
		if rootCADomain != "" {
			domains = []string{pki.GetRootCALiteralName(rootCADomain)}
		} else {
			baseDir, err := getEffectiveWorkDir()
			if err != nil {
				return err
			}
			dirs, err := pki.ListDirectories(baseDir)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			for _, dir := range dirs {
				if exists, _ := pki.DirectoryExists(filepath.Join(baseDir, dir, "ca")); exists {
					domains = append(domains, dir)
				}
			}
		}

		type trustEntry struct {
			// Name is the root CA's literal name (dots replaced by dashes), as
			// `root-ca list` reports it.
			Name        string `json:"name"`
			Certificate string `json:"certificate"`
			Trusted     bool   `json:"trusted"`
			Detail      string `json:"detail,omitempty"`
		}

		entries := make([]trustEntry, 0, len(domains))
		for _, domain := range domains {
			_, certPath, err := rootCAPaths(domain)
			if err != nil {
				return err
			}
			entry := trustEntry{Name: domain, Certificate: certPath}
			if exists, _ := pki.FileExists(certPath); !exists {
				entry.Detail = "no Root CA certificate at this path"
			} else if out, err := pki.RunQuiet(pki.MacOSTrustStatusArgs(certPath)); err != nil {
				entry.Detail = firstLine(out)
			} else {
				entry.Trusted = true
			}
			entries = append(entries, entry)
		}

		if outputFormat == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(entries)
		}

		if len(entries) == 0 {
			fmt.Println("No Root CAs found.")
			return nil
		}
		fmt.Println("Root CA trust (macOS system keychain):")
		for _, e := range entries {
			if e.Trusted {
				fmt.Printf("  %s%-24s ✓ trusted%s\n", ansiGreen, e.Name, ansiReset)
				continue
			}
			fmt.Printf("  %s%-24s ✗ not trusted%s", ansiRed, e.Name, ansiReset)
			if e.Detail != "" {
				fmt.Printf(" (%s)", e.Detail)
			}
			fmt.Println()
		}
		return nil
	},
}

// trustCertPath validates the platform and the domain, and returns the Root CA
// certificate to hand to the system trust store.
func trustCertPath() (string, error) {
	if err := requireMacOS(); err != nil {
		return "", err
	}
	if rootCADomain == "" {
		return "", fmt.Errorf("root CA domain name is required")
	}
	_, certPath, err := rootCAPaths(rootCADomain)
	if err != nil {
		return "", err
	}
	if exists, _ := pki.FileExists(certPath); !exists {
		return "", fmt.Errorf("no Root CA certificate at %s — run `homepki root-ca --domain %s` first", certPath, rootCADomain)
	}
	return certPath, nil
}

func requireMacOS() error {
	if !pki.IsMacOS() {
		return fmt.Errorf("trust store management is implemented for macOS only (this host is %s)", runtime.GOOS)
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func init() {
	rootCmd.AddCommand(trustCmd)
	trustCmd.AddCommand(trustInstallCmd, trustUninstallCmd, trustStatusCmd)

	for _, c := range []*cobra.Command{trustInstallCmd, trustUninstallCmd} {
		c.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
		c.MarkFlagRequired("domain")
	}
	trustStatusCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (default: every Root CA in the workdir)")
	trustStatusCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
}
