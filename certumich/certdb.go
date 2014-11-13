//
//  certdb -- write certs out to database for further processing
//
//  Operates on U_ Mich_ certificate dump CSV files_
//
//  The data files used are from
//  https://scans.io/study/umich-https
//
//  John Nagle
//  SiteTruth
//  October, 2014
//
package certumich

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
)
import "certscan/util"
import "strings"

//
//  Records per database load
//
const RECMAX = 10000 // after this many, load the database
//
//
//  Certdb -- database access object
//
type Certdb struct {
	dbcon   *sql.DB
	cloader util.SQLdataloader
	dloader util.SQLdataloader
	ploader util.SQLdataloader
}

//
//  Parameters for LOAD DATA INFILE LOCAL for the three tables
//
var CLOADPARAMS = "INTO TABLE certs"
var DLOADPARAMS = "INTO TABLE domains"
var PLOADPARAMS = "INTO TABLE policies"

//
//  Connect -- use database connection
//
func (d *Certdb) Connect(db *sql.DB, verbose bool) error {
	d.dbcon = db
	//  Prepare the three database table loaders - certs, domains, and policies.
	d.cloader.Open(CLOADPARAMS, d.dbcon, RECMAX, verbose)
	d.dloader.Open(DLOADPARAMS, d.dbcon, RECMAX, verbose)
	d.ploader.Open(PLOADPARAMS, d.dbcon, RECMAX, verbose)
	return nil
}

//
//  Disconnect -- done with DB connection
//
func (d *Certdb) Disconnect() error {
	defer func() { // make sure everything closes, even if fail
		_ = d.cloader.Close()
		_ = d.dloader.Close()
		_ = d.ploader.Close()
	}()
	//  Finish all files, with final write, flush, and database load
	err := d.cloader.Close()
	if err != nil {
		return err
	}
	err = d.dloader.Close()
	if err != nil {
		return err
	}
	err = d.ploader.Close()
	if err != nil {
		return err
	}
	//  Ought to commit here, but LOAD DATA INFILE implies commit
	return nil
}

//
//  Insertcert -- insert cert record
//
//  This requires updates to three tables.
//
func (d *Certdb) Insertcert(c *Processedcert) error {
	cline := c.PackcertforSQL()
	dlines := c.PackdomainsforSQL()
	plines := c.PackpoliciesforSQL()
	//  Write cert, domain, and policy load files
	err := d.cloader.Write(cline) // single line
	if err != nil {
		return err
	}
	err = d.dloader.Write(strings.Join(dlines, "")) // multiple lines 
	if err != nil {
		return err
	}
	err = d.ploader.Write(strings.Join(plines, "")) // multiple lines
	if err != nil {
		return err
	}
	return nil
}
