package cmd

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/bcollard/homepki/pkg/pki"
	"github.com/spf13/cobra"
)

var (
	revokeServer string
	revokeClient string
	revokeCert   string
	revokeReason string
)

// crlFlagUsage documents --validity for the commands that sign CRLs.
var crlFlagUsage = fmt.Sprintf("How long the CRLs stay current (their nextUpdate): days (90d) or a duration (24h). "+
	"Clients reject a CRL past it; run 'homepki crl' to re-sign (default %dd)", pki.CRLValidityDays)

var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a leaf certificate and publish the Intermediate CA's CRL",
	Long: `Revoke a server or client certificate issued by an Intermediate CA.

The serial number is added to the intermediate's certificate revocation list,
which the command re-signs, together with the Root CA's (empty) CRL. Three files
are written:

  <intermediate>/<intermediate>-intermediate-ca.crl   the intermediate's CRL
  ca/<root>-root-ca.crl                               the root's CRL
  <intermediate>/<intermediate>-crl-chain.crl         both, for servers that
                                                      check every tier

The CRL is the only record of revocations: homepki reads the existing one and
appends to it. The certificate files are left in place; 'list' reports them
as revoked. Re-issuing the name with --force gives it a new serial that is not
revoked.`,
	Example: `  # Revoke a client certificate
  homepki revoke --domain runlocal.dev --intermediate bu1 --client my-client

  # Revoke a server certificate, with a reason
  homepki revoke --domain runlocal.dev --intermediate bu1 --server kong-gateway --reason keyCompromise

  # Revoke a certificate signed with 'homepki sign' and written elsewhere
  homepki revoke --domain runlocal.dev --intermediate bu1 --cert ./my-service.crt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if rootCADomain == "" {
			return fmt.Errorf("root CA domain name is required")
		}
		if intermediateCAName == "" {
			return fmt.Errorf("intermediate CA name is required")
		}
		reason, err := pki.ParseRevocationReason(revokeReason)
		if err != nil {
			return err
		}
		validity, err := parseValidity(pki.CRLValidityDays)
		if err != nil {
			return err
		}

		workDir, _, err := rootCAPaths(rootCADomain)
		if err != nil {
			return err
		}
		interFiles := intermediateCAFiles(workDir, intermediateCAName)
		certPath := revokeCert
		switch {
		case revokeServer != "":
			certPath = filepath.Join(interFiles.dir, "server-tls", revokeServer+".crt")
		case revokeClient != "":
			certPath = filepath.Join(interFiles.dir, "client-tls", revokeClient+".crt")
		}

		cas, err := loadCAs(workDir)
		if err != nil {
			return err
		}
		cert, err := pki.LoadCert(certPath)
		if err != nil {
			return fmt.Errorf("certificate to revoke: %w", err)
		}
		if err := cert.CheckSignatureFrom(cas.inter); err != nil {
			return fmt.Errorf("%s was not issued by Intermediate CA %s, so its CRL cannot revoke it: %w",
				certPath, intermediateCAName, err)
		}
		prev, err := pki.LoadCRL(interFiles.crl, cas.inter)
		if err != nil {
			return fmt.Errorf("%w\n\nDelete the file to start a new, empty CRL", err)
		}
		if e := pki.FindRevoked(prev, cert.SerialNumber); e != nil {
			fmt.Printf("%s is already revoked (since %s).\n", certPath, e.RevocationTime.Format("2006-01-02"))
			return nil
		}

		fmt.Printf("Revoking %s (serial %x) under %s/%s\n", cert.Subject.CommonName, cert.SerialNumber, rootCADomain, intermediateCAName)
		entry := x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: time.Now(),
			ReasonCode:     reason,
		}
		if err := publishCRLs(workDir, cas, prev, []x509.RevocationListEntry{entry}, validity); err != nil {
			return err
		}
		fmt.Println("Certificate revoked. Reload servers that read the CRL.")
		return nil
	},
}

var crlCmd = &cobra.Command{
	Use:   "crl",
	Short: "Write or re-sign the CRLs of an Intermediate CA and its Root CA",
	Long: `Write the certificate revocation lists of an Intermediate CA and its Root CA,
keeping every revocation already recorded.

Use it to get CRL files before anything is revoked — a server configured with a
CRL refuses to start without one — or to push nextUpdate forward before the
current CRLs go stale.`,
	Example: `  homepki crl --domain runlocal.dev --intermediate bu1
  homepki crl --domain runlocal.dev --intermediate bu1 --validity 7d`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if rootCADomain == "" {
			return fmt.Errorf("root CA domain name is required")
		}
		if intermediateCAName == "" {
			return fmt.Errorf("intermediate CA name is required")
		}
		validity, err := parseValidity(pki.CRLValidityDays)
		if err != nil {
			return err
		}
		workDir, _, err := rootCAPaths(rootCADomain)
		if err != nil {
			return err
		}
		cas, err := loadCAs(workDir)
		if err != nil {
			return err
		}
		prev, err := pki.LoadCRL(intermediateCAFiles(workDir, intermediateCAName).crl, cas.inter)
		if err != nil {
			return fmt.Errorf("%w\n\nDelete the file to start a new, empty CRL", err)
		}
		return publishCRLs(workDir, cas, prev, nil, validity)
	},
}

// caPair holds both CA tiers above a leaf, keys included.
type caPair struct {
	root, inter       *x509.Certificate
	rootKey, interKey crypto.Signer
}

// loadCAs reads the Root CA and the Intermediate CA named by the flags.
func loadCAs(workDir string) (caPair, error) {
	var p caPair
	var err error
	literal := pki.GetRootCALiteralName(rootCADomain)
	if p.root, p.rootKey, err = rootCAFiles(workDir, literal).load("Root CA"); err != nil {
		return p, err
	}
	if p.inter, p.interKey, err = intermediateCAFiles(workDir, intermediateCAName).load("Intermediate CA"); err != nil {
		return p, err
	}
	return p, nil
}

// publishCRLs re-signs the intermediate's CRL with add appended, re-signs the
// root's CRL, and writes both plus the chain file.
func publishCRLs(workDir string, cas caPair, prevInter *x509.RevocationList, add []x509.RevocationListEntry, validity time.Duration) error {
	literal := pki.GetRootCALiteralName(rootCADomain)
	rootFiles := rootCAFiles(workDir, literal)
	interFiles := intermediateCAFiles(workDir, intermediateCAName)

	prevRoot, err := pki.LoadCRL(rootFiles.crl, cas.root)
	if err != nil {
		return fmt.Errorf("%w\n\nDelete the file to start a new, empty CRL", err)
	}
	interCRL, err := pki.SignCRL(prevInter, add, validity, cas.inter, cas.interKey)
	if err != nil {
		return err
	}
	rootCRL, err := pki.SignCRL(prevRoot, nil, validity, cas.root, cas.rootKey)
	if err != nil {
		return err
	}

	chain := crlChainPath(interFiles, intermediateCAName)
	if err := pki.WriteCRLs(interFiles.crl, interCRL); err != nil {
		return err
	}
	if err := pki.WriteCRLs(rootFiles.crl, rootCRL); err != nil {
		return err
	}
	if err := pki.WriteCRLs(chain, interCRL, rootCRL); err != nil {
		return err
	}
	fmt.Printf("Wrote %s (%d revoked, next update %s)\n", interFiles.crl,
		len(interCRL.RevokedCertificateEntries), interCRL.NextUpdate.Format("2006-01-02 15:04"))
	fmt.Printf("Wrote %s\nWrote %s\n", rootFiles.crl, chain)
	return nil
}

func init() {
	rootCmd.AddCommand(revokeCmd, crlCmd)

	revokeCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	revokeCmd.Flags().StringVarP(&intermediateCAName, "intermediate", "i", "", "Intermediate CA name (e.g., bu1)")
	revokeCmd.Flags().StringVarP(&revokeServer, "server", "s", "", "Server certificate to revoke, by name")
	revokeCmd.Flags().StringVarP(&revokeClient, "client", "c", "", "Client certificate to revoke, by name")
	revokeCmd.Flags().StringVar(&revokeCert, "cert", "", "Path of a certificate to revoke (e.g. one signed with 'homepki sign --out')")
	revokeCmd.Flags().StringVar(&revokeReason, "reason", "unspecified", "Revocation reason (RFC 5280): "+strings.Join(pki.RevocationReasons(), ", "))
	revokeCmd.Flags().StringVar(&validityFlag, "validity", "", crlFlagUsage)
	revokeCmd.MarkFlagRequired("domain")
	revokeCmd.MarkFlagRequired("intermediate")
	revokeCmd.MarkFlagsOneRequired("server", "client", "cert")
	revokeCmd.MarkFlagsMutuallyExclusive("server", "client", "cert")

	crlCmd.Flags().StringVarP(&rootCADomain, "domain", "d", "", "Root CA domain name (e.g., runlocal.dev)")
	crlCmd.Flags().StringVarP(&intermediateCAName, "intermediate", "i", "", "Intermediate CA name (e.g., bu1)")
	crlCmd.Flags().StringVar(&validityFlag, "validity", "", crlFlagUsage)
	crlCmd.MarkFlagRequired("domain")
	crlCmd.MarkFlagRequired("intermediate")
}
