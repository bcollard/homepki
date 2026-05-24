package cmd

import (
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

		rootCALiteralName := pki.GetRootCALiteralName(rootCADomain)
		baseDir, err := getEffectiveWorkDir()
		if err != nil {
			return err
		}
		workDir := filepath.Join(baseDir, rootCALiteralName)
		rootCADir := filepath.Join(workDir, "ca")
		intermediateCADir := filepath.Join(workDir, intermediateCAName)

		// Check if Root CA exists
		if exists, err := pki.DirectoryExists(rootCADir); err != nil {
			return err
		} else if !exists {
			return fmt.Errorf("root CA directory %s does not exist. Please create the Root CA first", rootCADir)
		}

		fmt.Printf("Initializing Intermediate CA %s for %s\n", intermediateCAName, rootCADomain)

		// Create directories
		if err := pki.CreateDirectory(intermediateCADir); err != nil {
			return err
		}
		if err := pki.CreateDirectory(filepath.Join(intermediateCADir, "db")); err != nil {
			return err
		}
		if err := pki.CreatePrivateDirectory(filepath.Join(intermediateCADir, "private")); err != nil {
			return err
		}

		// Create DB files
		if err := pki.WriteFile(filepath.Join(intermediateCADir, "db", "index.db"), ""); err != nil {
			return err
		}
		if err := pki.WriteFile(filepath.Join(intermediateCADir, "db", "serial"), "1000\n"); err != nil {
			return err
		}

		// Generate Intermediate CA config
		intermediateCAConfContent := fmt.Sprintf(`# Include defaults
.include %s/%s-defaults.conf

### TLS CA
# used for the intermediate CA CSR
[ req ]
distinguished_name      = tls_ca_dn                 # DN section
req_extensions          = tls_ca_ext             # Desired extensions

# used for the intermediate CA CSR
[ tls_ca_dn ]
organizationName        = %s
organizationalUnitName  = %s
commonName              = %s.%s

# used for the intermediate CA CSR
[ tls_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true,pathlen:0


# only used when signing leaf certificates (client or server)
[ ca ]
default_ca              = CA_default                          # The default ca section

[ CA_default ]
certificate             = %s/%s-intermediate-ca.crt               # The CA cert
dir                     = %s                   # Where everything is kept
private_key             = %s/private/%s-intermediate-ca.key   # The CA private key
database                = %s/db/index.db           # The CA database
serial                  = %s/db/serial             # The current serial number
policy                  = match_pol                     # The CA policy
new_certs_dir           = %s                       # New certs will be placed here
default_md              = sha256                              # MD to use
name_opt                = multiline,-esc_msb,utf8                                       # Subject DN display options
default_days            = 2190                                # How long to certify for
x509_extensions         = tls_ca_ext                          # Desired extensions
copy_extensions         = copy                                # Copy SAN (and other extensions) from the CSR into the signed cert

[ match_pol ]
countryName             = optional              # Must match 'NO'
stateOrProvinceName     = optional              # Included if present
localityName            = optional              # Included if present
organizationName        = match                 # Must match "%s"
organizationalUnitName  = match                 # Must match "%s"
commonName              = supplied              # Must be present

# only used when signing leaf server certificates
[ server_ext ]
keyUsage                = critical,digitalSignature,keyEncipherment
basicConstraints        = CA:false
extendedKeyUsage        = serverAuth
subjectKeyIdentifier    = hash

# only used when signing leaf client certificates
[ client_ext ]
keyUsage                = critical,digitalSignature
basicConstraints        = CA:false
extendedKeyUsage        = clientAuth
subjectKeyIdentifier    = hash
`, workDir, rootCALiteralName, rootCALiteralName, intermediateCAName, intermediateCAName, rootCADomain, intermediateCADir, intermediateCAName, intermediateCADir, intermediateCADir, intermediateCAName, intermediateCADir, intermediateCADir, intermediateCADir, rootCALiteralName, intermediateCAName)

		intermediateCAConfPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s.conf", intermediateCAName))
		if err := pki.WriteFile(intermediateCAConfPath, intermediateCAConfContent); err != nil {
			return err
		}

		// OpenSSL req
		keyPath := filepath.Join(intermediateCADir, "private", fmt.Sprintf("%s-intermediate-ca.key", intermediateCAName))
		csrPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s-intermediate-ca.csr", intermediateCAName))
		if err := pki.RunCommand("openssl", "req", "-new", "-nodes", "-sha256", "-newkey", "rsa:2048",
			"-config", intermediateCAConfPath,
			"-keyout", keyPath,
			"-out", csrPath); err != nil {
			return err
		}

		// Sign with Root CA
		rootCAConfPath := filepath.Join(rootCADir, fmt.Sprintf("%s.conf", rootCALiteralName))
		crtPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s-intermediate-ca.crt", intermediateCAName))
		if err := pki.RunCommand("openssl", "ca", "-batch",
			"-config", rootCAConfPath,
			"-extensions", "signing_ca_ext",
			"-in", csrPath,
			"-out", crtPath); err != nil {
			return err
		}

		// Create chain
		rootCACrtPath := filepath.Join(rootCADir, fmt.Sprintf("%s-root-ca.crt", rootCALiteralName))
		chainPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s-intermediate-ca-chain.crt", intermediateCAName))

		// Concatenate intermediate and root certs
		// We can use cat command or read/write files in Go. Using cat via shell is easier if we want to be lazy, but Go is better.
		// Let's use Go.
		// Actually, the shell script uses `cat ... > ...` and then `sed` to clean it up.
		// The sed command: sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p'
		// This is to remove text before/after the PEM block if any. OpenSSL usually outputs text info in the cert file unless -notext is used (which I don't see in the script, wait, `cert_opt = no_header` in defaults might help but `openssl ca` adds text by default).
		// The script does `openssl ca ... -out ...`.
		// Let's just run the cat command for now, or implement it in Go.

		// Reading files
		intermediateCrt, err := pki.ReadFile(crtPath)
		if err != nil {
			return err
		}
		rootCrt, err := pki.ReadFile(rootCACrtPath)
		if err != nil {
			return err
		}

		// Simple concatenation
		chainContent := string(intermediateCrt) + string(rootCrt)

		// Write chain
		if err := pki.WriteFile(chainPath, chainContent); err != nil {
			return err
		}

		// The sed part in the script seems to be cleaning up the chain file.
		// "Suppress the certificate info from the chain"
		// I'll implement a helper to clean PEM files if needed, but for now let's assume the user wants the chain.
		// If I want to replicate the sed behavior:
		// sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p'
		// This keeps only the PEM blocks.

		if err := pki.CleanPEMFile(chainPath); err != nil {
			return err
		}

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
	intermediateCACmd.MarkFlagRequired("domain")
	intermediateCACmd.MarkFlagRequired("name")

	intermediateCACmd.AddCommand(intermediateCAListCmd)
	intermediateCAListCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	intermediateCAListCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	intermediateCAListCmd.MarkFlagRequired("domain")
}
