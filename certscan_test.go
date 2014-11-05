//
//  certscan_test -- SSL certificate analyzer
//
//  Package tests.
//
//  John Nagle
//  SiteTruth
//  October, 2014
//
package main

import "testing"

import "certscan/certumich"
import "certscan/util"

//
//  Testdb  -- test database connection
//
func Testdb(t *testing.T) {
    //  Test-only database parameters.
    const user = "certscan"
    const pass = "aaaa"
    const database = "certscan"
    var db certumich.Certdb       // working database
    err := db.Connect(user, pass, database)    // open
    if err != nil {
        t.Logf(err.Error())
        t.FailNow()
        }
    defer db.Disconnect()                        // close at exit
    //  ***MORE***
}

//
//  TestTLDinfo -- test domain info loading
//
func TestTLDinfo(t *testing.T) {
	const domainsuffixfile = "/home/john/projects/gocode/src/certscan/data/effective_tld_names.dat" // should be overrideable
	var TLDinfo util.DomainSuffixes                                                                 // top-level domain info
	err := TLDinfo.Loadpublicsuffixlist(domainsuffixfile)                                           // load list
	if err != nil {
		t.Logf(err.Error())
		t.FailNow()
	}
	TLDinfo.Dump()
}

//
//  TestCAinfo  -- test CA info loading
//
func TestCAinfo(t *testing.T) {
	const caoidfile = "/home/john/projects/gocode/src/certscan/data/catypetable.csv" // should be overrideable
	var CAinfo util.CApolicyinfo                                                     // policy info
	err := CAinfo.Loadoidinfo(caoidfile)                                             // load list
	if err != nil {
		t.Logf(err.Error())
		t.FailNow()
	}
	CAinfo.Dump()
}
