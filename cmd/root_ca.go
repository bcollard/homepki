package cmd

import (
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"

	"github.com/bcollard/homepki/pkg/pki"
	"github.com/spf13/cobra"
)

var rootCADomain string

var rootCACmd = &cobra.Command{
	Use:   "root-ca",
	Short: "Generate a self-signed Root CA",
	Example: `  # Generate a Root CA for runlocal.dev
  homepki root-ca --domain runlocal.dev

  # Generate a Root CA with an ECDSA P-256 key
  homepki root-ca --domain runlocal.dev --key-type ecdsa

  # Generate a Root CA valid for 10 years
  homepki root-ca --domain runlocal.dev --validity 3650d

  # Restrict the Root CA to names under klimax.internal
  homepki root-ca --domain klimax.internal --name-constraint "permitted;DNS:.klimax.internal"

  # List existing Root CAs
  homepki root-ca list

  # List as JSON
  homepki root-ca list -o json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if rootCADomain == "" {
			return fmt.Errorf("root CA domain name is required")
		}
		if err := pki.ValidateKeyType(keyType); err != nil {
			return err
		}
		validity, err := parseValidity(pki.CAValidityDays)
		if err != nil {
			return err
		}

		rootCALiteralName := pki.GetRootCALiteralName(rootCADomain)
		baseDir, err := getEffectiveWorkDir()
		if err != nil {
			return err
		}
		workDir := filepath.Join(baseDir, rootCALiteralName)
		files := rootCAFiles(workDir, rootCALiteralName)

		if present := pathsPresent(files.cert); len(present) > 0 {
			if !forceGenerate {
				return fmt.Errorf("a Root CA for %s already exists at %s\n\n"+
					"Re-generating it creates a new key, which orphans every "+
					"Intermediate CA and leaf certificate beneath it. Pass --force to replace it anyway",
					rootCADomain, files.cert)
			}
			fmt.Printf("--force: replacing the existing Root CA for %s\n", rootCADomain)
			fmt.Println("Every Intermediate CA and leaf certificate under it will stop verifying — re-generate them.")
		}

		fmt.Printf("Initializing Root CA for %s in %s\n", rootCADomain, workDir)
		nc, err := parseNameConstraints(rootCADomain, "")
		if err != nil {
			return err
		}

		if err := pki.CreateDirectory(files.dir); err != nil {
			return err
		}
		if err := pki.CreatePrivateDirectory(filepath.Dir(files.key)); err != nil {
			return err
		}

		key, err := pki.GenerateKey(keyType)
		if err != nil {
			return err
		}
		cert, err := pki.SelfSignRoot(key, pkix.Name{
			Organization: []string{rootCALiteralName},
			CommonName:   rootCADomain,
		}, nc, validity)
		if err != nil {
			return err
		}
		if err := pki.WriteKey(files.key, key); err != nil {
			return err
		}
		if err := pki.WriteCerts(files.cert, cert); err != nil {
			return err
		}
		if err := removeOpenSSLLeftovers(files.dir,
			files.crl, // signed by the replaced key
			filepath.Join(files.dir, rootCALiteralName+".conf"),
			filepath.Join(files.dir, rootCALiteralName+"-root-ca.csr"),
			filepath.Join(workDir, rootCALiteralName+"-defaults.conf")); err != nil {
			return err
		}

		fmt.Printf("Wrote %s\nWrote %s\n", files.key, files.cert)
		fmt.Println("Root CA generated successfully.")
		return nil
	},
}

var rootCAListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls", "l"},
	Short:   "List Root CAs with expiry and self-signature validity",
	Example: `  homepki root-ca list
  homepki root-ca list -o json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		baseDir, err := getEffectiveWorkDir()
		if err != nil {
			return err
		}
		if exists, _ := pki.DirectoryExists(baseDir); !exists {
			if outputFormat == "json" {
				fmt.Println("[]")
			} else {
				fmt.Println("No Root CAs found.")
			}
			return nil
		}

		dirs, err := pki.ListDirectories(baseDir)
		if err != nil {
			return err
		}

		var entries []certEntry
		for _, dir := range dirs {
			if exists, _ := pki.DirectoryExists(filepath.Join(baseDir, dir, "ca")); exists {
				certPath := filepath.Join(baseDir, dir, "ca", fmt.Sprintf("%s-root-ca.crt", dir))
				expiry, daysLeft, err := pki.GetCertExpiry(certPath)
				expiryStr, days := "unknown", -1
				if err == nil {
					expiryStr = expiry.Format("2006-01-02")
					days = daysLeft
				}
				entries = append(entries, certEntry{
					name:     dir,
					expiry:   expiryStr,
					daysLeft: days,
					chainErr: pki.VerifyRootCert(certPath),
				})
			}
		}

		if outputFormat != "json" {
			fmt.Println("Root CAs:")
		}
		return printCerts(entries)
	},
}

func init() {
	rootCmd.AddCommand(rootCACmd)
	rootCACmd.AddCommand(rootCAListCmd)
	rootCACmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	rootCACmd.Flags().StringVar(&keyType, "key-type", "rsa", keyTypeFlagUsage)
	rootCACmd.Flags().BoolVarP(&forceGenerate, "force", "f", false, "Replace an existing Root CA (orphans every certificate under it)")
	rootCACmd.Flags().StringVar(&validityFlag, "validity", "", validityFlagUsage("Root CA", pki.CAValidityDays))
	rootCACmd.Flags().StringArrayVar(&nameConstraints, "name-constraint", nil, nameConstraintFlagUsage)
	rootCACmd.MarkFlagRequired("domain")
	rootCAListCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
}
