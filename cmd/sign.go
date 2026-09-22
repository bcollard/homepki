package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/bcollard/homepki/pkg/pki"
	"github.com/spf13/cobra"
)

var (
	signCSRPath string
	signType    string
	signName    string
	signOut     string
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign an external CSR with an Intermediate CA",
	Long: `Sign a certificate signing request produced elsewhere — by a service that
generated its own key, by cert-manager, or by hand with openssl req.

homepki never sees the private key: only the request goes in, only the
certificate comes out. Subject Alternative Names are taken from the request.

The Intermediate CA's policy requires the request's subject to carry the Root
CA's organization and the intermediate's organizational unit, with any common
name. homepki checks that before calling openssl and prints the subject you
need.`,
	Example: `  # Sign a request as a server certificate
  homepki sign --domain runlocal.dev --intermediate bu1 --csr ./my-service.csr

  # Sign it as a client certificate, under a chosen name
  homepki sign --domain runlocal.dev --intermediate bu1 --csr ./my-client.csr \
    --type client --name my-client

  # Write the certificate outside the PKI tree
  homepki sign --domain runlocal.dev --intermediate bu1 --csr ./my-service.csr \
    --out ./my-service.crt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if rootCADomain == "" {
			return fmt.Errorf("root CA domain name is required")
		}
		if intermediateCAName == "" {
			return fmt.Errorf("intermediate CA name is required")
		}
		if signCSRPath == "" {
			return fmt.Errorf("a certificate signing request is required (--csr)")
		}

		var extension, leafSubdir, useVerb string
		switch signType {
		case "server":
			extension, leafSubdir, useVerb = "server_ext", "server-tls", "Serve"
		case "client":
			extension, leafSubdir, useVerb = "client_ext", "client-tls", "Present"
		default:
			return fmt.Errorf("--type must be server or client, got %q", signType)
		}

		rootCALiteralName := pki.GetRootCALiteralName(rootCADomain)
		baseDir, err := getEffectiveWorkDir()
		if err != nil {
			return err
		}
		workDir := filepath.Join(baseDir, rootCALiteralName)
		intermediateCADir := filepath.Join(workDir, intermediateCAName)

		intermediateCACrtPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s-intermediate-ca.crt", intermediateCAName))
		if exists, err := pki.FileExists(intermediateCACrtPath); err != nil {
			return err
		} else if !exists {
			return fmt.Errorf("intermediate CA certificate %s does not exist. Please create the Intermediate CA first", intermediateCACrtPath)
		}

		csr, err := pki.LoadCSR(signCSRPath)
		if err != nil {
			return err
		}
		exampleCN := fmt.Sprintf("my-service.%s.%s", intermediateCAName, rootCADomain)
		if err := pki.ValidateCSRSubject(csr, rootCALiteralName, intermediateCAName, exampleCN); err != nil {
			return fmt.Errorf("%s: %w", signCSRPath, err)
		}

		name := signName
		if name == "" {
			if name, err = pki.LeafNameFromCN(csr.Subject.CommonName); err != nil {
				return err
			}
		}

		leafDir := filepath.Join(intermediateCADir, leafSubdir)
		if err := pki.CreateDirectory(leafDir); err != nil {
			return err
		}
		crtPath := signOut
		if crtPath == "" {
			crtPath = filepath.Join(leafDir, fmt.Sprintf("%s.crt", name))
		}

		present := pathsPresent(crtPath)
		if len(present) > 0 && !forceGenerate {
			return fmt.Errorf("a certificate already exists at %s\n\n"+
				"Pass --force to replace it, or choose another --name or --out", crtPath)
		}
		// Even with no file in the way, the CA database may already hold a row for
		// this subject, which openssl refuses to sign twice.
		if forceGenerate {
			if err := replaceLeaf(intermediateCADir, csr.Subject.CommonName, present); err != nil {
				return err
			}
		}

		if len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) == 0 {
			fmt.Println("Warning: the request carries no Subject Alternative Names — most TLS clients reject a certificate matched on its common name alone.")
		}

		fmt.Printf("Signing %s as a %s certificate for %s under %s/%s\n",
			signCSRPath, signType, csr.Subject.CommonName, rootCADomain, intermediateCAName)

		// The intermediate config sets copy_extensions = copy, so the SANs requested
		// in the CSR are carried over; -extensions pins basicConstraints, keyUsage
		// and extendedKeyUsage so a request cannot ask for more than a leaf.
		intermediateCAConfPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s.conf", intermediateCAName))
		if err := pki.RunCommand("openssl", "ca", "-batch",
			"-config", intermediateCAConfPath,
			"-extensions", extension,
			"-in", signCSRPath,
			"-out", crtPath,
			"-days", "365"); err != nil {
			return err
		}

		chainPath := filepath.Join(intermediateCADir, fmt.Sprintf("%s-intermediate-ca-chain.crt", intermediateCAName))
		fmt.Printf("Certificate written to %s\n", crtPath)
		fmt.Printf("%s it with the chain file %s; the private key stays wherever you generated it.\n", useVerb, chainPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	signCmd.Flags().StringVarP(&intermediateCAName, "intermediate", "i", "", "Intermediate CA name (e.g., bu1)")
	signCmd.Flags().StringVar(&signCSRPath, "csr", "", "Path to the PEM certificate signing request to sign")
	signCmd.Flags().StringVar(&signType, "type", "server", "Certificate type: server or client")
	signCmd.Flags().StringVar(&signName, "name", "", "Name for the certificate file (default: first label of the request's common name)")
	signCmd.Flags().StringVar(&signOut, "out", "", "Write the certificate here instead of the intermediate's server-tls/ or client-tls/")
	signCmd.Flags().BoolVarP(&forceGenerate, "force", "f", false, "Replace an existing certificate for the same subject")
	signCmd.MarkFlagRequired("domain")
	signCmd.MarkFlagRequired("intermediate")
	signCmd.MarkFlagRequired("csr")
}
