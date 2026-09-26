package cmd

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bcollard/homepki/pkg/pki"
	"github.com/spf13/cobra"
)

// trustStoreNames are the values --store accepts.
var trustStoreNames = []string{"system", "nss", "java"}

// trustStoresFlag backs --store.
var trustStoresFlag []string

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Add a Root CA to the system, Firefox/NSS and Java trust stores",
	Long: `Manage the trust stores that accept a homepki Root CA.

Three kinds of store are covered, selected with --store:

  system  macOS: the System keychain (Safari, Chrome, curl, Go, Secure Transport).
          Linux: the distribution's anchor directory, followed by
          update-ca-certificates, update-ca-trust or trust extract-compat.
  nss     Every Firefox profile, and on Linux the Chrome/Chromium NSS database,
          through NSS's certutil (brew install nss, apt install libnss3-tools).
  java    The cacerts keystore of the JDK at $JAVA_HOME, through keytool.

Without --store, every store available on this host is used: system, plus nss
when a profile and certutil are both found, plus java when JAVA_HOME is set.

Servers must still present the intermediate: serve the leaf with
<intermediate>-intermediate-ca-chain.crt, or clients cannot build the path to
the trusted root.

The system store, and a cacerts file the current user cannot write, need root:
homepki runs those commands under sudo, which may prompt for your password.`,
}

var trustInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Trust a Root CA in every available store (system store needs sudo)",
	Example: `  homepki trust install --domain runlocal.dev
  homepki trust install --domain runlocal.dev --store nss,java`,
	RunE: func(cmd *cobra.Command, args []string) error {
		certPath, cert, err := trustRootCert()
		if err != nil {
			return err
		}
		targets, err := resolveTrustTargets(pki.GetRootCALiteralName(rootCADomain), certPath, cert, true)
		if err != nil {
			return err
		}

		var failed []string
		for _, t := range targets {
			if ok, _ := t.status(); ok {
				fmt.Printf("%-6s already trusted in %s\n", t.store, t.location)
				continue
			}
			fmt.Printf("%-6s adding to %s\n", t.store, t.location)
			if t.sudo {
				fmt.Println("       sudo may ask for your password.")
			}
			if err := t.install(); err != nil {
				failed = append(failed, fmt.Sprintf("%s (%s): %v", t.store, t.location, err))
				continue
			}
			if ok, detail := t.status(); !ok {
				failed = append(failed, fmt.Sprintf("%s (%s): added but still not trusted: %s", t.store, t.location, detail))
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("the Root CA could not be trusted everywhere:\n  %s", strings.Join(failed, "\n  "))
		}
		fmt.Printf("Root CA for %s is trusted in %d store(s).\n", rootCADomain, len(targets))
		for _, t := range targets {
			if t.store != "system" {
				fmt.Println("Restart Firefox and Java processes to pick it up.")
				break
			}
		}
		fmt.Println("Serve leaves with the intermediate chain file so clients can reach this root.")
		return nil
	},
}

var trustUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop trusting a Root CA in every available store (system store needs sudo)",
	Example: `  homepki trust uninstall --domain runlocal.dev
  homepki trust uninstall --domain runlocal.dev --store nss`,
	RunE: func(cmd *cobra.Command, args []string) error {
		certPath, cert, err := trustRootCert()
		if err != nil {
			return err
		}
		targets, err := resolveTrustTargets(pki.GetRootCALiteralName(rootCADomain), certPath, cert, true)
		if err != nil {
			return err
		}

		var failed []string
		keychain := false
		for _, t := range targets {
			keychain = keychain || (t.store == "system" && runtime.GOOS == "darwin")
			if t.present != nil && !t.present() {
				fmt.Printf("%-6s not present in %s\n", t.store, t.location)
				continue
			}
			fmt.Printf("%-6s removing from %s\n", t.store, t.location)
			if t.sudo {
				fmt.Println("       sudo may ask for your password.")
			}
			if err := t.uninstall(); err != nil {
				failed = append(failed, fmt.Sprintf("%s (%s): %v", t.store, t.location, err))
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("the Root CA could not be removed everywhere:\n  %s", strings.Join(failed, "\n  "))
		}
		fmt.Printf("Root CA for %s is no longer trusted.\n", rootCADomain)
		if keychain {
			fmt.Println("The certificate itself may remain in the System keychain; remove it with Keychain Access if you want it gone.")
		}
		return nil
	},
}

var trustStatusCmd = &cobra.Command{
	Use:     "status",
	Aliases: []string{"st"},
	Short:   "Report which trust stores accept a Root CA",
	Example: `  homepki trust status
  homepki trust status --domain runlocal.dev
  homepki trust status --store system -o json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateStoreNames(); err != nil {
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

		type storeEntry struct {
			Store    string `json:"store"`
			Location string `json:"location"`
			Trusted  bool   `json:"trusted"`
			Detail   string `json:"detail,omitempty"`
		}
		type trustEntry struct {
			// Name is the root CA's literal name (dots replaced by dashes), as
			// `root-ca list` reports it.
			Name        string `json:"name"`
			Certificate string `json:"certificate"`
			// Trusted is true when every store checked accepts the root.
			Trusted bool         `json:"trusted"`
			Detail  string       `json:"detail,omitempty"`
			Stores  []storeEntry `json:"stores"`
		}

		entries := make([]trustEntry, 0, len(domains))
		for i, literal := range domains {
			_, certPath, err := rootCAPaths(literal)
			if err != nil {
				return err
			}
			entry := trustEntry{Name: literal, Certificate: certPath, Stores: []storeEntry{}}
			cert, err := pki.LoadCert(certPath)
			if err != nil {
				entry.Detail = "no Root CA certificate at this path"
				entries = append(entries, entry)
				continue
			}
			// Notes about skipped stores are the same for every root; print them once.
			targets, err := resolveTrustTargets(literal, certPath, cert, i == 0 && outputFormat != "json")
			if err != nil {
				return err
			}
			entry.Trusted = true
			for _, t := range targets {
				ok, detail := t.status()
				entry.Stores = append(entry.Stores, storeEntry{Store: t.store, Location: t.location, Trusted: ok, Detail: detail})
				if !ok {
					entry.Trusted = false
					if entry.Detail == "" {
						entry.Detail = t.store + ": " + detail
					}
				}
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
		fmt.Println("Root CA trust:")
		for _, e := range entries {
			if e.Trusted {
				fmt.Printf("  %s%-24s ✓ trusted%s\n", ansiGreen, e.Name, ansiReset)
			} else if len(e.Stores) == 0 {
				fmt.Printf("  %s%-24s ✗ %s%s\n", ansiRed, e.Name, e.Detail, ansiReset)
			} else {
				state := "not trusted"
				for _, st := range e.Stores {
					if st.Trusted {
						state = "partly trusted"
					}
				}
				fmt.Printf("  %s%-24s ✗ %s%s\n", ansiRed, e.Name, state, ansiReset)
			}
			for _, s := range e.Stores {
				mark, color := "✓", ansiGreen
				if !s.Trusted {
					mark, color = "✗", ansiRed
				}
				fmt.Printf("      %s%s %-6s%s %s", color, mark, s.Store, ansiReset, s.Location)
				if s.Detail != "" {
					fmt.Printf(" (%s)", s.Detail)
				}
				fmt.Println()
			}
		}
		return nil
	},
}

// trustTarget is one trust store a Root CA can be added to.
type trustTarget struct {
	store    string // system, nss or java
	location string // keychain, anchor file, NSS database directory, cacerts
	sudo     bool   // whether install and uninstall run under sudo
	install  func() error
	// uninstall removes the root; present, when set, says whether there is
	// anything to remove, since certutil and keytool fail on a missing entry.
	uninstall func() error
	present   func() bool
	status    func() (bool, string)
}

// resolveTrustTargets lists the stores --store selects on this host. Without
// --store, stores that are not available are skipped, with a note when notes
// is true; a store named explicitly must be available.
func resolveTrustTargets(literal, certPath string, cert *x509.Certificate, notes bool) ([]trustTarget, error) {
	if err := validateStoreNames(); err != nil {
		return nil, err
	}
	explicit := map[string]bool{}
	for _, s := range trustStoresFlag {
		explicit[s] = true
	}
	auto := len(explicit) == 0
	wanted := func(store string) bool { return auto || explicit[store] }
	skip := func(store, why string) error {
		if !auto {
			return fmt.Errorf("--store %s: %s", store, why)
		}
		if notes {
			fmt.Printf("Skipping %s: %s\n", store, why)
		}
		return nil
	}

	var targets []trustTarget
	if wanted("system") {
		t, why := systemTarget(literal, certPath, cert)
		if t != nil {
			targets = append(targets, *t)
		} else if err := skip("system", why); err != nil {
			return nil, err
		}
	}
	if wanted("nss") {
		t, why := nssTargets(literal, certPath)
		if len(t) > 0 {
			targets = append(targets, t...)
		} else if why != "" {
			if err := skip("nss", why); err != nil {
				return nil, err
			}
		}
	}
	if wanted("java") {
		t, why := javaTarget(literal, certPath)
		if t != nil {
			targets = append(targets, *t)
		} else if why != "" {
			if err := skip("java", why); err != nil {
				return nil, err
			}
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no trust store available on this host (%s): the system store is supported on macOS and Linux", runtime.GOOS)
	}
	return targets, nil
}

// systemTarget returns the platform trust store, or why there is none.
func systemTarget(literal, certPath string, cert *x509.Certificate) (*trustTarget, string) {
	switch runtime.GOOS {
	case "darwin":
		return &trustTarget{
			store:    "system",
			location: "/Library/Keychains/System.keychain",
			sudo:     os.Geteuid() != 0,
			install: func() error {
				return pki.RunInteractive(pki.Sudo(pki.MacOSTrustInstallArgs(certPath)))
			},
			uninstall: func() error {
				return pki.RunInteractive(pki.Sudo(pki.MacOSTrustUninstallArgs(certPath)))
			},
			status: func() (bool, string) {
				if out, err := pki.RunQuiet(pki.MacOSTrustStatusArgs(certPath)); err != nil {
					return false, firstLine(out)
				}
				return true, ""
			},
		}, ""
	case "linux":
		store, ok := pki.DetectLinuxStore()
		if !ok {
			return nil, "no known CA anchor directory on this Linux host (install the ca-certificates package)"
		}
		anchor := store.AnchorPath(literal)
		runAll := func(cmds [][]string) error {
			for _, argv := range cmds {
				if err := pki.RunInteractive(pki.Sudo(argv)); err != nil {
					return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
				}
			}
			return nil
		}
		return &trustTarget{
			store:     "system",
			location:  anchor,
			sudo:      os.Geteuid() != 0,
			install:   func() error { return runAll(store.InstallCommands(certPath, literal)) },
			uninstall: func() error { return runAll(store.UninstallCommands(literal)) },
			status: func() (bool, string) {
				if err := pki.SystemTrusts(cert); err != nil {
					if exists, _ := pki.FileExists(anchor); exists {
						return false, "anchor present but the bundle does not include it; run " + strings.Join(store.Update, " ")
					}
					return false, "not in the system bundle"
				}
				return true, ""
			},
		}, ""
	}
	return nil, "not supported on " + runtime.GOOS
}

// nssTargets returns one target per NSS database found in the home directory.
// The reason is empty when there is simply no Firefox profile, which is not
// worth a note.
func nssTargets(literal, certPath string) ([]trustTarget, string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err.Error()
	}
	dbs := pki.NSSDatabases(home)
	if len(dbs) == 0 {
		if len(trustStoresFlag) > 0 {
			return nil, "no Firefox profile or NSS database found under " + home
		}
		return nil, ""
	}
	certutil, err := pki.FindCertutil()
	if err != nil {
		return nil, fmt.Sprintf("%d Firefox/NSS database(s) found, but certutil is missing "+
			"(brew install nss, apt install libnss3-tools, dnf install nss-tools)", len(dbs))
	}
	nick := pki.NSSNickname(literal)
	var targets []trustTarget
	for _, db := range dbs {
		targets = append(targets, trustTarget{
			store:    "nss",
			location: db[strings.IndexByte(db, ':')+1:],
			install: func() error {
				_, err := runQuietErr(pki.NSSInstallArgs(certutil, db, nick, certPath))
				return err
			},
			uninstall: func() error {
				_, err := runQuietErr(pki.NSSUninstallArgs(certutil, db, nick))
				return err
			},
			present: func() bool {
				_, err := pki.RunQuiet([]string{certutil, "-L", "-d", db, "-n", nick})
				return err == nil
			},
			status: func() (bool, string) {
				if out, err := pki.RunQuiet(pki.NSSStatusArgs(certutil, db, nick)); err != nil {
					return false, lastLine(out)
				}
				return true, ""
			},
		})
	}
	return targets, ""
}

// javaTarget returns the cacerts keystore of $JAVA_HOME. The reason is empty
// when JAVA_HOME is unset and java was not asked for.
func javaTarget(literal, certPath string) (*trustTarget, string) {
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome == "" && len(trustStoresFlag) == 0 {
		return nil, ""
	}
	cacerts, keytool, err := pki.JavaTrustStore(javaHome)
	if err != nil {
		return nil, err.Error()
	}
	alias := pki.JavaAlias(literal)
	sudo := !pki.IsWritable(cacerts)
	wrap := func(argv []string) []string {
		if sudo {
			return pki.Sudo(argv)
		}
		return argv
	}
	present := func() bool {
		_, err := pki.RunQuiet(pki.JavaStatusArgs(keytool, cacerts, alias))
		return err == nil
	}
	return &trustTarget{
		store:    "java",
		location: cacerts,
		sudo:     sudo && os.Geteuid() != 0,
		install: func() error {
			return pki.RunInteractive(wrap(pki.JavaInstallArgs(keytool, cacerts, alias, certPath)))
		},
		uninstall: func() error {
			return pki.RunInteractive(wrap(pki.JavaUninstallArgs(keytool, cacerts, alias)))
		},
		present: present,
		status: func() (bool, string) {
			if !present() {
				return false, "alias " + alias + " not in the keystore"
			}
			return true, ""
		},
	}, ""
}

// runQuietErr runs a command and folds its output into the error.
func runQuietErr(argv []string) (string, error) {
	out, err := pki.RunQuiet(argv)
	if err != nil {
		return out, fmt.Errorf("%w: %s", err, lastLine(out))
	}
	return out, nil
}

func validateStoreNames() error {
	for _, s := range trustStoresFlag {
		known := false
		for _, n := range trustStoreNames {
			known = known || s == n
		}
		if !known {
			return fmt.Errorf("unknown trust store %q (want one of: %s)", s, strings.Join(trustStoreNames, ", "))
		}
	}
	return nil
}

// trustRootCert validates the domain and returns the Root CA certificate to
// hand to the trust stores.
func trustRootCert() (string, *x509.Certificate, error) {
	if rootCADomain == "" {
		return "", nil, fmt.Errorf("root CA domain name is required")
	}
	_, certPath, err := rootCAPaths(rootCADomain)
	if err != nil {
		return "", nil, err
	}
	if exists, _ := pki.FileExists(certPath); !exists {
		return "", nil, fmt.Errorf("no Root CA certificate at %s — run `homepki root-ca --domain %s` first", certPath, rootCADomain)
	}
	cert, err := pki.LoadCert(certPath)
	if err != nil {
		return "", nil, err
	}
	return certPath, cert, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func init() {
	rootCmd.AddCommand(trustCmd)
	trustCmd.AddCommand(trustInstallCmd, trustUninstallCmd, trustStatusCmd)

	storeUsage := "Trust stores to use (repeatable or comma-separated): " + strings.Join(trustStoreNames, ", ") +
		" (default: every store available on this host)"
	for _, c := range []*cobra.Command{trustInstallCmd, trustUninstallCmd} {
		c.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
		c.Flags().StringSliceVar(&trustStoresFlag, "store", nil, storeUsage)
		c.MarkFlagRequired("domain")
	}
	trustStatusCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (default: every Root CA in the workdir)")
	trustStatusCmd.Flags().StringSliceVar(&trustStoresFlag, "store", nil, storeUsage)
	trustStatusCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
}
