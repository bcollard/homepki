package cmd

import (
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

  # List existing Root CAs
  homepki root-ca list

  # List as JSON
  homepki root-ca list -o json`,
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
		rootCADir := filepath.Join(workDir, "ca")

		fmt.Printf("Initializing Root CA for %s in %s\n", rootCADomain, workDir)

		// Create directories
		if err := pki.CreateDirectory(rootCADir); err != nil {
			return err
		}
		if err := pki.CreateDirectory(filepath.Join(rootCADir, "db")); err != nil {
			return err
		}
		if err := pki.CreatePrivateDirectory(filepath.Join(rootCADir, "private")); err != nil {
			return err
		}

		// Create DB files
		if err := pki.WriteFile(filepath.Join(rootCADir, "db", "index.db"), ""); err != nil {
			return err
		}
		if err := pki.WriteFile(filepath.Join(rootCADir, "db", "serial"), "1000\n"); err != nil {
			return err
		}

		// Generate defaults.conf
		if err := pki.GenerateDefaultsConf(workDir, rootCALiteralName); err != nil {
			return err
		}

		// Generate Root CA config
		rootCAConfContent := fmt.Sprintf(`# Include defaults
.include %s/%s-defaults.conf

### ROOT CA
# used for the root CA CSR
[ req ]
distinguished_name      = root_ca_dn                          # DN section
req_extensions          = root_ca_ext                         # Desired extensions

# used for the root CA CSR
[ root_ca_dn ]
organizationName        = %s
commonName              = %s

# used for the root CA CSR
[ root_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true,pathlen:1

# used for self-signing the root CA
# also used when signing intermediate CAs (accounts/organizations)
[ ca ]
default_ca              = CA_default                          # The default ca section

[ CA_default ]
certificate             = %s/%s-root-ca.crt            # The CA cert
dir                     = %s                                                # Where everything is kept
private_key             = %s/private/%s-root-ca.key    # The CA private key
database                = %s/db/index.db                                    # The CA database
serial                  = %s/db/serial                                      # The current serial number
policy                  = match_pol                                                     # The CA policy
new_certs_dir           = %s                                                # New certs will be placed here
default_md              = sha256                                                        # MD to use
name_opt                = multiline,-esc_msb,utf8                                       # Subject DN display options
default_days            = 2190                                                          # How long to certify for
x509_extensions         = root_ca_ext                                                   # Desired extensions

[ match_pol ]
countryName             = optional              # Must match 'NO'
stateOrProvinceName     = optional              # Included if present
localityName            = optional              # Included if present
organizationName        = match                 # Must match "%s"
organizationalUnitName  = optional              # Included if present
commonName              = supplied              # Must be present


# only used when signing intermediate CAs (accounts/organizations)
[ signing_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true,pathlen:0
subjectKeyIdentifier    = hash
`, workDir, rootCALiteralName, rootCALiteralName, rootCADomain, rootCADir, rootCALiteralName, rootCADir, rootCADir, rootCALiteralName, rootCADir, rootCADir, rootCADir, rootCALiteralName)

		rootCAConfPath := filepath.Join(rootCADir, fmt.Sprintf("%s.conf", rootCALiteralName))
		if err := pki.WriteFile(rootCAConfPath, rootCAConfContent); err != nil {
			return err
		}

		// OpenSSL req
		keyPath := filepath.Join(rootCADir, "private", fmt.Sprintf("%s-root-ca.key", rootCALiteralName))
		csrPath := filepath.Join(rootCADir, fmt.Sprintf("%s-root-ca.csr", rootCALiteralName))
		if err := pki.RunCommand("openssl", "req", "-new", "-nodes", "-sha256", "-newkey", "rsa:2048",
			"-config", rootCAConfPath,
			"-keyout", keyPath,
			"-out", csrPath); err != nil {
			return err
		}

		// OpenSSL ca selfsign
		crtPath := filepath.Join(rootCADir, fmt.Sprintf("%s-root-ca.crt", rootCALiteralName))
		if err := pki.RunCommand("openssl", "ca", "-selfsign", "-batch",
			"-config", rootCAConfPath,
			"-in", csrPath,
			"-out", crtPath, "-certform", "PEM"); err != nil {
			return err
		}

		fmt.Println("Root CA generated successfully.")
		return nil
	},
}

var rootCAListCmd = &cobra.Command{
	Use:   "list",
	Short: "List Root CAs with expiry and self-signature validity",
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
	rootCACmd.MarkFlagRequired("domain")
	rootCAListCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
}
