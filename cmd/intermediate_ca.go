package cmd

import (
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"

	"github.com/bcollard/homepki/pkg/pki"
	"github.com/spf13/cobra"
)

var intermediateCAName string

var intermediateCACmd = &cobra.Command{
	Use:   "intermediate-ca",
	Short: "Generate an Intermediate CA signed by a Root CA",
	Example: `  # Generate an Intermediate CA named 'bu1' for runlocal.dev
  homepki intermediate-ca --domain runlocal.dev --name bu1

  # Generate one with an ECDSA P-256 key
  homepki intermediate-ca --domain runlocal.dev --name bu1 --key-type ecdsa

  # Restrict the Intermediate CA to names under bu1.klimax.internal
  homepki intermediate-ca --domain klimax.internal --name bu1 \
    --name-constraint "permitted;DNS:.bu1.klimax.internal"

  # List existing Intermediate CAs with chain verification
  homepki intermediate-ca list --domain runlocal.dev

  # List as JSON
  homepki intermediate-ca list --domain runlocal.dev -o json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if rootCADomain == "" {
			return fmt.Errorf("root CA domain name is required")
		}
		if intermediateCAName == "" {
			return fmt.Errorf("intermediate CA name is required")
		}
		if err := pki.ValidateKeyType(keyType); err != nil {
			return err
		}

		rootCALiteralName := pki.GetRootCALiteralName(rootCADomain)
		baseDir, err := getEffectiveWorkDir()
		if err != nil {
			return err
		}
		workDir := filepath.Join(baseDir, rootCALiteralName)
		rootFiles := rootCAFiles(workDir, rootCALiteralName)
		files := intermediateCAFiles(workDir, intermediateCAName)

		if exists, err := pki.DirectoryExists(rootFiles.dir); err != nil {
			return err
		} else if !exists {
			return fmt.Errorf("root CA directory %s does not exist. Please create the Root CA first", rootFiles.dir)
		}
		rootCert, rootKey, err := rootFiles.load("Root CA")
		if err != nil {
			return err
		}

		if present := pathsPresent(files.cert); len(present) > 0 {
			if !forceGenerate {
				return fmt.Errorf("an Intermediate CA named %q already exists at %s\n\n"+
					"Re-generating it creates a new key, which orphans every "+
					"leaf certificate beneath it. Pass --force to replace it anyway, or pick another name",
					intermediateCAName, files.cert)
			}
			fmt.Printf("--force: replacing the existing Intermediate CA %s\n", intermediateCAName)
			fmt.Println("Every leaf certificate under it will stop verifying — re-generate them.")
		}

		fmt.Printf("Initializing Intermediate CA %s for %s\n", intermediateCAName, rootCADomain)
		nc, err := parseNameConstraints(rootCADomain, intermediateCAName)
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
		cert, err := pki.SignIntermediate(key.Public(), pkix.Name{
			Organization:       []string{rootCALiteralName},
			OrganizationalUnit: []string{intermediateCAName},
			CommonName:         fmt.Sprintf("%s.%s", intermediateCAName, rootCADomain),
		}, nc, rootCert, rootKey)
		if err != nil {
			return err
		}

		chainPath := filepath.Join(files.dir, fmt.Sprintf("%s-intermediate-ca-chain.crt", intermediateCAName))
		if err := pki.WriteKey(files.key, key); err != nil {
			return err
		}
		if err := pki.WriteCerts(files.cert, cert); err != nil {
			return err
		}
		if err := pki.WriteCerts(chainPath, cert, rootCert); err != nil {
			return err
		}
		if err := removeOpenSSLLeftovers(files.dir,
			filepath.Join(files.dir, intermediateCAName+".conf"),
			filepath.Join(files.dir, intermediateCAName+"-intermediate-ca.csr"),
			filepath.Join(files.dir, intermediateCAName+"-signing-ext.conf")); err != nil {
			return err
		}

		fmt.Printf("Wrote %s\nWrote %s\nWrote %s\n", files.key, files.cert, chainPath)
		fmt.Println("Intermediate CA generated successfully.")
		return nil
	},
}

var intermediateCAListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls", "l"},
	Short:   "List Intermediate CAs with expiry and chain verification against the Root CA",
	Example: `  homepki intermediate-ca list --domain runlocal.dev
  homepki intermediate-ca list --domain runlocal.dev -o json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if rootCADomain == "" {
			return fmt.Errorf("root CA domain name is required")
		}
		rootCALiteralName := pki.GetRootCALiteralName(rootCADomain)
		baseDir, err := getEffectiveWorkDir()
		if err != nil {
			return err
		}
		workDir := filepath.Join(baseDir, rootCALiteralName)

		if exists, _ := pki.DirectoryExists(workDir); !exists {
			return fmt.Errorf("root CA directory %s does not exist", workDir)
		}

		rootCACertPath := filepath.Join(workDir, "ca", fmt.Sprintf("%s-root-ca.crt", rootCALiteralName))

		dirs, err := pki.ListDirectories(workDir)
		if err != nil {
			return err
		}

		var entries []certEntry
		for _, dir := range dirs {
			if dir == "ca" {
				continue
			}
			if exists, _ := pki.DirectoryExists(filepath.Join(workDir, dir, "private")); exists {
				certPath := filepath.Join(workDir, dir, fmt.Sprintf("%s-intermediate-ca.crt", dir))
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
					chainErr: pki.VerifyIntermediateCert(certPath, rootCACertPath),
				})
			}
		}

		if outputFormat != "json" {
			fmt.Printf("Intermediate CAs for %s:\n", rootCADomain)
		}
		return printCerts(entries)
	},
}

func init() {
	rootCmd.AddCommand(intermediateCACmd)
	intermediateCACmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	intermediateCACmd.Flags().StringVarP(&intermediateCAName, "name", "n", "", "Intermediate CA name (e.g., bu1)")
	intermediateCACmd.Flags().StringVar(&keyType, "key-type", "rsa", keyTypeFlagUsage)
	intermediateCACmd.Flags().BoolVarP(&forceGenerate, "force", "f", false, "Replace an existing Intermediate CA (orphans every certificate under it)")
	intermediateCACmd.Flags().StringArrayVar(&nameConstraints, "name-constraint", nil, nameConstraintFlagUsage)
	intermediateCACmd.MarkFlagRequired("domain")
	intermediateCACmd.MarkFlagRequired("name")

	intermediateCACmd.AddCommand(intermediateCAListCmd)
	intermediateCAListCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	intermediateCAListCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	intermediateCAListCmd.MarkFlagRequired("domain")
}
