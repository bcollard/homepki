package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/bcollard/homepki/pkg/pki"
	"github.com/spf13/cobra"
)

var clientName string

var clientCertCmd = &cobra.Command{
	Use:   "client-cert",
	Short: "Generate a Client Certificate",
	Example: `  # Generate a client certificate for 'my-client'
  homepki client-cert --domain runlocal.dev --intermediate siemens --client my-client

  # List existing client certificates
  homepki client-cert list --domain runlocal.dev --intermediate siemens`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if rootCADomain == "" {
			return fmt.Errorf("root CA domain name is required")
		}
		if intermediateCAName == "" {
			return fmt.Errorf("intermediate CA name is required")
		}
		if clientName == "" {
			return fmt.Errorf("client name is required")
		}

		rootCALiteralName := pki.GetRootCALiteralName(rootCADomain)
		baseDir, err := getEffectiveWorkDir()
		if err != nil {
			return err
		}
		workDir := filepath.Join(baseDir, rootCALiteralName)
		intermediateCADir := filepath.Join(workDir, intermediateCAName)
		clientDir := filepath.Join(intermediateCADir, "client-tls")

		// Check if Intermediate CA certificate exists
		intermediateCACrtPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s-intermediate-ca.crt", intermediateCAName))
		if exists, err := pki.FileExists(intermediateCACrtPath); err != nil {
			return err
		} else if !exists {
			return fmt.Errorf("intermediate CA certificate %s does not exist. Please create the Intermediate CA first", intermediateCACrtPath)
		}

		fmt.Printf("Generating Client Certificate %s for %s under %s\n", clientName, intermediateCAName, rootCADomain)

		// Create directories
		if err := pki.CreateDirectory(clientDir); err != nil {
			return err
		}

		// Generate Client config
		clientConfContent := fmt.Sprintf(`# Include defaults
.include %s/%s-defaults.conf


### Client cert
[ req ]
distinguished_name      = client_dn                # DN section
req_extensions          = client_ext               # Desired extensions

[ client_dn ]
organizationName        = %s
organizationalUnitName  = %s
commonName              = %s.%s.%s

[ client_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:false
extendedKeyUsage        = clientAuth
subjectAltName          = critical, @client_alt_names

[ client_alt_names ]
DNS.1 = %s.%s.%s
`, workDir, rootCALiteralName, rootCALiteralName, intermediateCAName, clientName, intermediateCAName, rootCADomain, clientName, intermediateCAName, rootCADomain)

		clientConfPath := filepath.Join(clientDir, fmt.Sprintf("%s.conf", clientName))
		if err := pki.WriteFile(clientConfPath, clientConfContent); err != nil {
			return err
		}

		// OpenSSL req
		keyPath := filepath.Join(clientDir, fmt.Sprintf("%s.key", clientName))
		csrPath := filepath.Join(clientDir, fmt.Sprintf("%s.csr", clientName))
		if err := pki.RunCommand("openssl", "req", "-new", "-nodes", "-sha256", "-newkey", "rsa:2048",
			"-config", clientConfPath,
			"-keyout", keyPath,
			"-out", csrPath); err != nil {
			return err
		}

		// Sign with Intermediate CA
		intermediateCAConfPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s.conf", intermediateCAName))
		crtPath := filepath.Join(clientDir, fmt.Sprintf("%s.crt", clientName))
		if err := pki.RunCommand("openssl", "ca", "-batch",
			"-config", intermediateCAConfPath,
			"-extensions", "client_ext",
			"-in", csrPath,
			"-out", crtPath,
			"-days", "365"); err != nil {
			return err
		}

		fmt.Println("Client Certificate generated successfully.")
		return nil
	},
}

var clientCertListCmd = &cobra.Command{
	Use:   "list",
	Short: "List existing Client Certificates",
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
		clientDir := filepath.Join(intermediateCADir, "client-tls")

		if exists, _ := pki.DirectoryExists(clientDir); !exists {
			return fmt.Errorf("client certs directory %s does not exist", clientDir)
		}

		files, err := pki.ListFiles(clientDir, ".crt")
		if err != nil {
			return err
		}
		fmt.Printf("Existing Client Certificates for %s/%s:\n", rootCADomain, intermediateCAName)
		for _, file := range files {
			fmt.Printf("- %s\n", file)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(clientCertCmd)
	clientCertCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	clientCertCmd.Flags().StringVarP(&intermediateCAName, "intermediate", "i", "", "Intermediate CA name (e.g., siemens)")
	clientCertCmd.Flags().StringVarP(&clientName, "client", "c", "", "Client name (e.g., my-client)")
	clientCertCmd.MarkFlagRequired("domain")
	clientCertCmd.MarkFlagRequired("intermediate")
	clientCertCmd.MarkFlagRequired("client")

	clientCertCmd.AddCommand(clientCertListCmd)
	clientCertListCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	clientCertListCmd.Flags().StringVarP(&intermediateCAName, "intermediate", "i", "", "Intermediate CA name (e.g., siemens)")
	clientCertListCmd.MarkFlagRequired("domain")
	clientCertListCmd.MarkFlagRequired("intermediate")
}
