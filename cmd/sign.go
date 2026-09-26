package cmd

import (
	"crypto/x509/pkix"
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
name. A request that does not fit is rejected with the subject you need.`,
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

		validity, err := parseValidity(pki.LeafValidityDays)
		if err != nil {
			return err
		}

		var kind pki.LeafKind
		var leafSubdir, useVerb string
		switch signType {
		case "server":
			kind, leafSubdir, useVerb = pki.ServerLeaf, "server-tls", "Serve"
		case "client":
			kind, leafSubdir, useVerb = pki.ClientLeaf, "client-tls", "Present"
		default:
			return fmt.Errorf("--type must be server or client, got %q", signType)
		}

		rootCALiteralName := pki.GetRootCALiteralName(rootCADomain)
		baseDir, err := getEffectiveWorkDir()
		if err != nil {
			return err
		}
		workDir := filepath.Join(baseDir, rootCALiteralName)
		interFiles := intermediateCAFiles(workDir, intermediateCAName)
		intermediateCert, intermediateKey, err := interFiles.load("Intermediate CA")
		if err != nil {
			return err
		}
		rootCert, err := pki.LoadCert(rootCAFiles(workDir, rootCALiteralName).cert)
		if err != nil {
			return fmt.Errorf("root CA certificate: %w", err)
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

		leafDir := filepath.Join(interFiles.dir, leafSubdir)
		crtPath := signOut
		if crtPath == "" {
			crtPath = filepath.Join(leafDir, fmt.Sprintf("%s.crt", name))
		}
		if len(pathsPresent(crtPath)) > 0 {
			if !forceGenerate {
				return fmt.Errorf("a certificate already exists at %s\n\n"+
					"Pass --force to replace it, or choose another --name or --out", crtPath)
			}
			fmt.Printf("--force: replacing %s\n", crtPath)
		}

		sans := pki.SANsFromCSR(csr)
		if sans.Count() == 0 {
			fmt.Println("Warning: the request carries no Subject Alternative Names — most TLS clients reject a certificate matched on its common name alone.")
		}

		fmt.Printf("Signing %s as a %s certificate for %s under %s/%s\n",
			signCSRPath, signType, csr.Subject.CommonName, rootCADomain, intermediateCAName)

		// Only the subject fields the CA policy knows and the SANs are taken from
		// the request. Basic constraints and key usages are set by homepki, so a
		// request cannot ask for more than a leaf.
		subject := pkix.Name{
			Country:            csr.Subject.Country,
			Province:           csr.Subject.Province,
			Locality:           csr.Subject.Locality,
			Organization:       csr.Subject.Organization,
			OrganizationalUnit: csr.Subject.OrganizationalUnit,
			CommonName:         csr.Subject.CommonName,
		}
		cert, err := pki.SignLeaf(csr.PublicKey, subject, sans, kind, validity, intermediateCert, intermediateKey)
		if err != nil {
			return err
		}
		if err := checkLeaf(cert, intermediateCert, rootCert, kind, interFiles.cert); err != nil {
			return err
		}
		if signOut == "" {
			if err := pki.CreateDirectory(leafDir); err != nil {
				return err
			}
		}
		if err := pki.WriteCerts(crtPath, cert); err != nil {
			return err
		}

		chainPath := filepath.Join(interFiles.dir, fmt.Sprintf("%s-intermediate-ca-chain.crt", intermediateCAName))
		fmt.Printf("Certificate written to %s\n", crtPath)
		noteCapped(cert, intermediateCert, validity)
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
	signCmd.Flags().StringVar(&validityFlag, "validity", "", validityFlagUsage("certificate", pki.LeafValidityDays))
	signCmd.Flags().BoolVarP(&forceGenerate, "force", "f", false, "Replace an existing certificate at the output path")
	signCmd.MarkFlagRequired("domain")
	signCmd.MarkFlagRequired("intermediate")
	signCmd.MarkFlagRequired("csr")
}
