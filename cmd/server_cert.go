package cmd

import (
	"crypto/x509"
	"fmt"
	"path/filepath"

	"github.com/bcollard/homepki/pkg/pki"
	"github.com/spf13/cobra"
)

var (
	serverName string
	serverSANs []string
)

var serverCertCmd = &cobra.Command{
	Use:   "server-cert",
	Short: "Generate a server TLS certificate signed by an Intermediate CA",
	Example: `  # Generate a server certificate for 'kong-gateway'
  homepki server-cert --domain runlocal.dev --intermediate bu1 --server kong-gateway

  # Add extra Subject Alternative Names (auto-detected as IP or DNS,
  # or prefix with DNS:, IP:, email:, URI: to force a type)
  homepki server-cert --domain runlocal.dev --intermediate bu1 --server kong-gateway \
    --san kong.local --san 192.168.1.10 --san IP:::1 --san DNS:*.kong.local

  # Replace an existing certificate of the same name
  homepki server-cert --domain runlocal.dev --intermediate bu1 --server kong-gateway --force

  # List existing server certificates with chain verification
  homepki server-cert list --domain runlocal.dev --intermediate bu1

  # List as JSON
  homepki server-cert list --domain runlocal.dev --intermediate bu1 -o json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := generateLeaf(leafRequest{
			kind:   pki.ServerLeaf,
			label:  "server",
			subdir: "server-tls",
			name:   serverName,
			sans:   serverSANs,
			inUse:  "serving",
		}); err != nil {
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
	serverCertCmd.Flags().StringVar(&keyType, "key-type", "rsa", keyTypeFlagUsage)
	serverCertCmd.Flags().BoolVarP(&forceGenerate, "force", "f", false, "Replace an existing certificate of the same name (its key is regenerated)")
	serverCertCmd.Flags().StringArrayVar(&serverSANs, "san", nil, "Additional Subject Alternative Name (repeatable). Bare values are auto-detected as IP or DNS; prefix with DNS:, IP:, email:, or URI: to force a type")
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
