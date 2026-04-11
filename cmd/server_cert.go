package cmd

import (
	"crypto/x509"
	"fmt"
	"path/filepath"

	"github.com/bcollard/homepki/pkg/pki"
	"github.com/spf13/cobra"
)

var serverName string

var serverCertCmd = &cobra.Command{
	Use:   "server-cert",
	Short: "Generate a server TLS certificate signed by an Intermediate CA",
	Example: `  # Generate a server certificate for 'kong-gateway'
  homepki server-cert --domain runlocal.dev --intermediate bu1 --server kong-gateway

  # List existing server certificates with chain verification
  homepki server-cert list --domain runlocal.dev --intermediate bu1

  # List as JSON
  homepki server-cert list --domain runlocal.dev --intermediate bu1 -o json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if rootCADomain == "" {
			return fmt.Errorf("root CA domain name is required")
		}
		if intermediateCAName == "" {
			return fmt.Errorf("intermediate CA name is required")
		}
		if serverName == "" {
			return fmt.Errorf("server name is required")
		}

		rootCALiteralName := pki.GetRootCALiteralName(rootCADomain)
		baseDir, err := getEffectiveWorkDir()
		if err != nil {
			return err
		}
		workDir := filepath.Join(baseDir, rootCALiteralName)
		intermediateCADir := filepath.Join(workDir, intermediateCAName)
		serverDir := filepath.Join(intermediateCADir, "server-tls")

		// Check if Intermediate CA certificate exists
		intermediateCACrtPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s-intermediate-ca.crt", intermediateCAName))
		if exists, err := pki.FileExists(intermediateCACrtPath); err != nil {
			return err
		} else if !exists {
			return fmt.Errorf("intermediate CA certificate %s does not exist. Please create the Intermediate CA first", intermediateCACrtPath)
		}

		fmt.Printf("Generating Server Certificate %s for %s under %s\n", serverName, intermediateCAName, rootCADomain)

		// Create directories
		if err := pki.CreateDirectory(serverDir); err != nil {
			return err
		}

		// Generate Server config
		serverConfContent := fmt.Sprintf(`# Include defaults
.include %s/%s-defaults.conf


### Server cert
[ req ]
distinguished_name      = server_dn                # DN section
req_extensions          = server_ext               # Desired extensions

[ server_dn ]
organizationName        = %s
organizationalUnitName  = %s
commonName              = %s.%s.%s

[ server_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:false
extendedKeyUsage        = serverAuth
subjectAltName          = critical, @server_alt_names

[ server_alt_names ]
DNS.1 = %s.%s.%s
`, workDir, rootCALiteralName, rootCALiteralName, intermediateCAName, serverName, intermediateCAName, rootCADomain, serverName, intermediateCAName, rootCADomain)

		serverConfPath := filepath.Join(serverDir, fmt.Sprintf("%s.conf", serverName))
		if err := pki.WriteFile(serverConfPath, serverConfContent); err != nil {
			return err
		}

		// OpenSSL req
		keyPath := filepath.Join(serverDir, fmt.Sprintf("%s.key", serverName))
		csrPath := filepath.Join(serverDir, fmt.Sprintf("%s.csr", serverName))
		if err := pki.RunCommand("openssl", "req", "-new", "-nodes", "-sha256", "-newkey", "rsa:2048",
			"-config", serverConfPath,
			"-keyout", keyPath,
			"-out", csrPath); err != nil {
			return err
		}

		// Sign with Intermediate CA
		intermediateCAConfPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s.conf", intermediateCAName))
		crtPath := filepath.Join(serverDir, fmt.Sprintf("%s.crt", serverName))
		if err := pki.RunCommand("openssl", "ca", "-batch",
			"-config", intermediateCAConfPath,
			"-extensions", "server_ext",
			"-in", csrPath,
			"-out", crtPath,
			"-days", "365"); err != nil {
			return err
		}

		fmt.Println("Server Certificate generated successfully.")
		return nil
	},
}

var serverCertListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls", "l"},
	Short:   "List server certificates with expiry and chain verification against the Intermediate and Root CA",
	Example: `  homepki server-cert list --domain runlocal.dev --intermediate bu1
  homepki server-cert list --domain runlocal.dev --intermediate bu1 -o json`,
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
		intermediateCADir := filepath.Join(workDir, intermediateCAName)
		serverDir := filepath.Join(intermediateCADir, "server-tls")

		if exists, _ := pki.DirectoryExists(serverDir); !exists {
			if outputFormat != "json" {
				fmt.Printf("Server Certificates for %s/%s:\n", rootCADomain, intermediateCAName)
				fmt.Println("No server certificates found.")
			} else {
				fmt.Println("[]")
			}
			return nil
		}

		rootCACertPath := filepath.Join(workDir, "ca", fmt.Sprintf("%s-root-ca.crt", rootCALiteralName))
		intermediateCACertPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s-intermediate-ca.crt", intermediateCAName))

		files, err := pki.ListFiles(serverDir, ".crt")
		if err != nil {
			return err
		}

		var entries []certEntry
		for _, file := range files {
			certPath := filepath.Join(serverDir, file)
			expiry, daysLeft, err := pki.GetCertExpiry(certPath)
			expiryStr, days := "unknown", -1
			if err == nil {
				expiryStr = expiry.Format("2006-01-02")
				days = daysLeft
			}
			entries = append(entries, certEntry{
				name:     file,
				expiry:   expiryStr,
				daysLeft: days,
				chainErr: pki.VerifyLeafCert(certPath, intermediateCACertPath, rootCACertPath, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}),
			})
		}

		if outputFormat != "json" {
			fmt.Printf("Server Certificates for %s/%s:\n", rootCADomain, intermediateCAName)
		}
		return printCerts(entries)
	},
}

func init() {
	rootCmd.AddCommand(serverCertCmd)
	serverCertCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	serverCertCmd.Flags().StringVarP(&intermediateCAName, "intermediate", "i", "", "Intermediate CA name (e.g., bu1)")
	serverCertCmd.Flags().StringVarP(&serverName, "server", "s", "", "Server name (e.g., kong-gateway-clustering)")
	serverCertCmd.MarkFlagRequired("domain")
	serverCertCmd.MarkFlagRequired("intermediate")
	serverCertCmd.MarkFlagRequired("server")

	serverCertCmd.AddCommand(serverCertListCmd)
	serverCertListCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	serverCertListCmd.Flags().StringVarP(&intermediateCAName, "intermediate", "i", "", "Intermediate CA name (e.g., bu1)")
	serverCertListCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	serverCertListCmd.MarkFlagRequired("domain")
	serverCertListCmd.MarkFlagRequired("intermediate")
}
