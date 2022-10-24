// issuer.go -- issuer cert creation
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	"os"

	"github.com/opencoff/go-pki"
	flag "github.com/opencoff/pflag"
)

// Implement the 'issuer' command
func IssuerCert(db string, args []string) {
	fs := flag.NewFlagSet("issuer", flag.ExitOnError)
	fs.Usage = func() {
		issuerUsage(fs)
	}

	var yrs uint = 2
	var signer, envpw string

	fs.UintVarP(&yrs, "validity", "V", yrs, "Issue issuer certificate with `N` years validity")
	fs.StringVarP(&signer, "sign-with", "s", "", "Use `S` as the signing CA [root-CA]")
	fs.StringVarP(&envpw, "env-password", "E", "", "Use password from environment var `E`")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	args = fs.Args()
	if len(args) < 1 {
		warn("Insufficient arguments to 'issuer'\n")
		fs.Usage()
	}

	cn := args[0]

	ca := OpenCA(db, envpw)
	if len(signer) > 0 {
		ica, err := ca.FindCA(signer)
		if err != nil {
			die("can't find signer %s: %s", signer, err)
		}
		ca = ica
	}
	defer ca.Close()

	ci := &pki.CertInfo{
		Subject:    ca.Subject,
		Validity:   years(yrs),
	}
	ci.Subject.CommonName = cn

	// We don't encrypt issuer certs
	srv, err := ca.NewServerCert(ci, "")
	if err != nil {
		die("can't create issuer cert: %s", err)
	}

	Print("New issuer cert:\n%s\n", Cert(*srv.Certificate))
}

func issuerUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s issuer: Issue a new issuer certificate

Usage: %s DB issuer [options] CN

Where 'DB' is the CA Database file name and 'CN' is the CommonName for the issuer.

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}

