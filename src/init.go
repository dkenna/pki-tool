// init.go - init command implementation
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
        "log"
	"os"
	"time"

	"github.com/opencoff/go-pki"
	"github.com/dkenna/pki-tool/internal/utils"
	flag "github.com/opencoff/pflag"
  
  "gopkg.in/yaml.v3"
)

// Open an existing CA or fail
func OpenCA(db string, envpw string) *pki.CA {
	var pw string
	var err error

	if len(envpw) > 0 {
		pw = os.Getenv(envpw)
	} else {
		// we only ask _once_
		pw, err = utils.Askpass("Enter password for DB", false)
		if err != nil {
			die("%s", err)
		}
	}

	p := pki.Config{
		Passwd: pw,
	}
	ca, err := pki.New(&p, db, false)
	if err != nil {
		die("%s", err)
	}
	return ca
}

// initialize a CA in 'dbfile' or import from json
func InitCmd(dbfile string, args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fs.Usage = func() {
		initUsage(fs)
	}

        type YmlConfig struct {
                CommonName string `yaml:"cn"`
                Country string `yaml:"country"`
                Organization string `yaml:"organization"`
                OrganizationUnit string `yaml:"organization-unit"`
                Validity uint `yaml:"validity"`
        }

        var ymlPath string
	var cn, country, org, ou string
	var yrs uint
	var from string
	var envpw string

	fs.StringVarP(&ymlPath, "yaml-config", "c", "", "Path to YAML CA config file")
	fs.StringVarP(&envpw, "env-password", "E", "", "Use password from environment var `E`")
	fs.StringVarP(&from, "from-json", "j", "", "Initialize from an exported JSON dump")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	var pw string

	args = fs.Args()

	if len(envpw) > 0 {
		pw = os.Getenv(envpw)
	} else {
		pw, err = utils.Askpass("Enter password for DB", true)
		if err != nil {
			die("%s", err)
		}
	}

	var ca *pki.CA
	if len(from) > 0 {
		js, err := ioutil.ReadFile(from)
		if err != nil {
			die("can't read json: %s", err)
		}

		cfg := &pki.Config{
			Passwd: pw,
		}
		ca, err = pki.NewFromJSON(cfg, dbfile, string(js))
		if err != nil {
			die("%s", err)
		}
	} else if ymlPath != "" {
                var ymlConfig = YmlConfig{}

                ymlFile, err := ioutil.ReadFile(ymlPath)
                if err != nil {
                        log.Fatalf("ca.yml err:   #%v ", err)
                }
                err = yaml.Unmarshal(ymlFile, &ymlConfig)
                if err != nil {
                        log.Fatalf("error: %v", err)
                }
                cn = ymlConfig.CommonName
                country = ymlConfig.Country
                org = ymlConfig.Organization
                ou = ymlConfig.OrganizationUnit
                yrs = ymlConfig.Validity

		p := pki.Config{
			Passwd:   pw,
			Validity: years(yrs),

			Subject: pkix.Name{
				Country:            []string{country},
				Organization:       []string{org},
				OrganizationalUnit: []string{ou},
				CommonName:         cn,
			},
		}
		ca, err = pki.New(&p, dbfile, true)
		if err != nil {
			die("%s", err)
		}
	} else {
                fs.Usage()
                os.Exit(1)
        }

	Print("New CA cert:\n%s\n", Cert(*ca.Certificate))
}

func initUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s init: Initialize a new CA and cert store

This command initializes the given CA database and creates
a new root CA if needed.

Usage: %s DB init [options]

Where 'DB' is the CA Database file name and 'CN' is the CommonName for the CA.

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}

// convert duration in years to time.Duration
// 365.25 days/year * 24 hours/day
// .25 days/year = 24 hours / 4 = 6 hrs
func years(n uint) time.Duration {
	day := 24 * time.Hour
	return (6 * time.Hour) + (time.Duration(n*365) * day)
}
