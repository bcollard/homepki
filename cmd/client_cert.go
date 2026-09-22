package cmd

import (
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bcollard/homepki/pkg/pki"
	"github.com/spf13/cobra"
)

var clientName string

var clientCertCmd = &cobra.Command{
	Use:   "client-cert",
	Short: "Generate a client TLS certificate signed by an Intermediate CA",
	Example: `  # Generate a client certificate for 'my-client'
  homepki client-cert --domain runlocal.dev --intermediate bu1 --client my-client

  # Replace an existing certificate of the same name
  homepki client-cert --domain runlocal.dev --intermediate bu1 --client my-client --force

  # List existing client certificates with chain verification
  homepki client-cert list --domain runlocal.dev --intermediate bu1

  # List as JSON
  homepki client-cert list --domain runlocal.dev --intermediate bu1 -o json`,
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
		keyArgs, err := pki.KeyGenArgs(keyType)
		if err != nil {
			return err
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

		commonName := fmt.Sprintf("%s.%s.%s", clientName, intermediateCAName, rootCADomain)
		crtPath := filepath.Join(clientDir, fmt.Sprintf("%s.crt", clientName))
		keyPath := filepath.Join(clientDir, fmt.Sprintf("%s.key", clientName))
		csrPath := filepath.Join(clientDir, fmt.Sprintf("%s.csr", clientName))
		if present := pathsPresent(crtPath, keyPath, csrPath); len(present) > 0 {
			if !forceGenerate {
				return fmt.Errorf("a client certificate named %q already exists under %s/%s:\n  %s\n\n"+
					"Re-issuing overwrites its private key, so anything already authenticating with that pair breaks. "+
					"Pass --force to replace it, or issue under another name",
					clientName, rootCADomain, intermediateCAName, strings.Join(present, "\n  "))
			}
			if err := replaceLeaf(intermediateCADir, commonName, present); err != nil {
				return err
			}
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
		reqArgs := append([]string{"req", "-new", "-nodes", "-sha256"}, keyArgs...)
		reqArgs = append(reqArgs, "-config", clientConfPath, "-keyout", keyPath, "-out", csrPath)
		if err := pki.RunCommand("openssl", reqArgs...); err != nil {
			return err
		}

		// Sign with Intermediate CA
		intermediateCAConfPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s.conf", intermediateCAName))
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
	Use:     "list",
	Aliases: []string{"ls", "l"},
	Short:   "List client certificates with expiry and chain verification against the Intermediate and Root CA",
	Example: `  homepki client-cert list --domain runlocal.dev --intermediate bu1
  homepki client-cert list --domain runlocal.dev --intermediate bu1 -o json`,
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
			if outputFormat != "json" {
				fmt.Printf("Client Certificates for %s/%s:\n", rootCADomain, intermediateCAName)
				fmt.Println("No client certificates found.")
			} else {
				fmt.Println("[]")
			}
			return nil
		}

		rootCACertPath := filepath.Join(workDir, "ca", fmt.Sprintf("%s-root-ca.crt", rootCALiteralName))
		intermediateCACertPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s-intermediate-ca.crt", intermediateCAName))

		files, err := pki.ListFiles(clientDir, ".crt")
		if err != nil {
			return err
		}

		var entries []certEntry
		for _, file := range files {
			certPath := filepath.Join(clientDir, file)
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
				chainErr: pki.VerifyLeafCert(certPath, intermediateCACertPath, rootCACertPath, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}),
			})
		}

		if outputFormat != "json" {
			fmt.Printf("Client Certificates for %s/%s:\n", rootCADomain, intermediateCAName)
		}
		return printCerts(entries)
	},
}

func init() {
	rootCmd.AddCommand(clientCertCmd)
	clientCertCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	clientCertCmd.Flags().StringVarP(&intermediateCAName, "intermediate", "i", "", "Intermediate CA name (e.g., bu1)")
	clientCertCmd.Flags().StringVarP(&clientName, "client", "c", "", "Client name (e.g., my-client)")
	clientCertCmd.Flags().StringVar(&keyType, "key-type", "rsa", keyTypeFlagUsage)
	clientCertCmd.Flags().BoolVarP(&forceGenerate, "force", "f", false, "Replace an existing certificate of the same name (its key is regenerated)")
	clientCertCmd.MarkFlagRequired("domain")
	clientCertCmd.MarkFlagRequired("intermediate")
	clientCertCmd.MarkFlagRequired("client")

	clientCertCmd.AddCommand(clientCertListCmd)
	clientCertListCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	clientCertListCmd.Flags().StringVarP(&intermediateCAName, "intermediate", "i", "", "Intermediate CA name (e.g., bu1)")
	clientCertListCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	clientCertListCmd.MarkFlagRequired("domain")
	clientCertListCmd.MarkFlagRequired("intermediate")
}
