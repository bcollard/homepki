package cmd

import (
	"crypto/x509"
	"fmt"
	"path/filepath"

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
		if err := generateLeaf(leafRequest{
			kind:   pki.ClientLeaf,
			label:  "client",
			subdir: "client-tls",
			name:   clientName,
			sans:   nil,
			inUse:  "authenticating with",
		}); err != nil {
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
