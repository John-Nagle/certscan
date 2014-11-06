//
//  certscan -- SSL certificate analyzer
//
//  Operates on U. Mich. certificate dump CSV files.
//
//  The data files used are from
//  https://scans.io/study/umich-https
//
//  John Nagle
//  SiteTruth
//  October, 2014
//
package main

import "encoding/csv"
import "fmt"
import "flag"
import "os"
import "io"
import "bufio"
import "certscan/certumich"
import "certscan/util"

//
//  cmdoptions -- command line options
//
type cmdoptions struct {
                        // exclude record if lacks any of these properties.
                        // default is exclude, options override
	altname      bool   // lacks alt domain names
	org          bool   // lacks Organization (O) field
	valid        bool   // not valid cert
	browservalid bool   // not valid cert for any known browser cert chain
	casigned     bool   // CA (not self-signed) cert
	policy       string // Keep record only if policy matches ('DV', 'OV', 'EV', or an OID value)
	                    // other options
	outfilename  string // output CSV file if desired
	infilenames  []string // names of input files
	verbose      bool   // true if verbose for debug
	                    // database credentials
	user         string // database user
	pass         string // database password
	database     string // database name
}

//
//  Tallies
//
type tallies struct {
	in     int64 // records in
	out    int64 // records out
	errors int64 // errors
}

//
//  Globals
//
var cmdopts cmdoptions        // the keep/exclude options
var tally tallies               // error counts
var TLDinfo util.DomainSuffixes // top-level domain info
var CAinfo util.CApolicyinfo    // policy info

//
//  parseargs -- parse input args
//
//  usage: certscan [flags] [-o outfile] infile...
//
//  Returns outfilename, []infilenames
//
func parseargs(opts *cmdoptions) {
	//  Command line options
	flag.BoolVar(&opts.verbose, "v", false, "Verbose mode")
	flag.BoolVar(&opts.altname, "noaltname", false, "Keep record if no Alt Names")
	flag.BoolVar(&opts.org, "noorg", false, "Keep record if no Organization")
	flag.BoolVar(&opts.valid, "novalid", false, "Keep record if not valid cert")
	flag.BoolVar(&opts.browservalid, "nobrowservalid", false, "Keep record if not valid per Mozilla root cert list")
	flag.BoolVar(&opts.casigned, "nocasigned", false, "Keep record if not CA-signed (self-signed cert)")
	flag.StringVar(&opts.policy, "policy", "", "Keep record if policy matches ('DV', 'OV', 'EV', or an OID value)")
	infilenames := make([]string, 0)
	flag.StringVar(&opts.outfilename, "o", "", "Output file (csv format)")
	flag.StringVar(&opts.user, "user", "", "Database user name")
	flag.StringVar(&opts.pass, "pass", "", "Database password")
	flag.StringVar(&opts.database, "database", "", "Database name")
	flag.Parse() // parse command line
	if cmdopts.verbose { // dump args if verbose
		fmt.Println("Verbose mode.")
		fmt.Print("Output file: ", cmdopts.outfilename, "\n")
		fmt.Println("Input files: ")
		for i := range flag.Args() {
			fmt.Println(flag.Arg(i))
		}
	} // return infiles as array of strings
	for i := range flag.Args() {
		infilenames = append(infilenames, flag.Arg(i))
	}
    opts.infilenames = infilenames
}

type rechandler func([]string, *csv.Writer, *certumich.Certdb) error

//
//  keeptest -- do we want to keep this record?
//
func keeptest(cfields certumich.Processedcert) (bool, error) {
	keep := true // assume keep
	//  Valid flags check
	keep = keep && (cmdopts.valid || cfields.Valid)               // discard if not valid
	keep = keep && (cmdopts.browservalid || cfields.Is_browser_valid) // discard if not big-name browser valid
	keep = keep && (cmdopts.casigned || cfields.CAsigned)         // discard if self-signed
	//  Unpack subject info
	domain := cfields.Subject_commonname // Common Name, i.e. main domain
	//
	//  CA Policy check
	//
	if keep && cmdopts.policy != "" {
		find := false
		for i := range cfields.Policies { // for all fields
			field := cfields.Policies[i]
			keep = keep || cmdopts.policy == field   // if it matches an actual policy OID
			policyitem, ok := CAinfo.Getpolicy(field) // look up policy item
			if ok {
				fmt.Printf("Domain '%s' OID %s (%s) from CA %s\n", domain, field, policyitem.Policy, policyitem.CAname) // ***TEMP***
				find = find || policyitem.Policy == cmdopts.policy                                                     // keep if policy matches policy param
			}
		}
		keep = keep && find // don't keep unless find
	}
	//  Alt names check
	if keep && !cmdopts.altname { // if requiring alt names
		if len(cfields.Domains2ld) > 1 { // if multiple domain cert
			keep = true
			fmt.Printf("Multiple-domain cert: '%s' vs '%s'\n", cfields.Domains2ld[0], cfields.Domains2ld[1]) // ***TEMP***
		}
	}
	//  Has Organization field check
	if keep && !cmdopts.org {
		foundorg := cfields.Subject_organization != "" // test for presence of org
		keep = keep && foundorg                        // must have Organization field
	}
	return keep, nil // final result
}

//
//  dorec -- handle an input line record, already parsed into fields
//
func dorec(fields []string, outf *csv.Writer, outdb *certumich.Certdb) error {
	keep := false                                         // keep record for later processing?
	tally.in++                                            // count in
	var cfields certumich.Processedcert                   // cert in error format
	cfields, err := certumich.Unpackcert(fields, TLDinfo) // convert to structure format
	if err != nil {                                       // trouble
		msg := "INVALID RECORD FORMAT: " + err.Error() // create message
		certumich.Seterror(fields, msg)                // set in record for later use
		tally.errors++                                 // count errors
		keep = true                                    // force keep
	} else {
		keep, err = keeptest(cfields) // keep this record?
		if err != nil {               // trouble
			msg := "KEEP TEST FAILED: " + err.Error() // create message
			certumich.Seterror(fields, msg)           // set in record for later use
			tally.errors++                            // count errors
			keep = true                               // force keep
		}
	}
	if keep {
	    if outf != nil { // if output file
		    err := (*outf).Write(fields) // write output
		    tally.out++                  // count out
		    if err != nil {
			    panic(err) // fails
		    }
        }
        if outdb != nil { // if output database
            err := outdb.Insertcert(&cfields)
		    if err != nil {
			    panic(err) // fails
		    }
        }
	}
	if cmdopts.verbose {
		cfields.Dump()
	}
	return nil
}

//
//  readinputfile -- handle an input file
//
func readinputfile(infilename string, fn rechandler, outf *csv.Writer, outdb *certumich.Certdb) (int, error) {
	badlinecount := 0              // no bad lines yet
	fi, err := os.Open(infilename) // open input file
	if err != nil {
		panic(err) // Unable to open input, panicking
	}
	defer func() { // handle close
		if err := fi.Close(); err != nil {
			panic(err) // failed close is legit panic
		}
	}()
	r := bufio.NewReader(fi) // make a read buffer
	csvr := csv.NewReader(r) // make a CSV reader
	//  Set any CSV format parameters here if necessary.
	csvr.TrailingComma = true                   // allow trailing comma (deprecated)
	csvr.FieldsPerRecord = certumich.Fieldcount // number of fields per record
	//  Read the file
	for { // until EOF
		fields, err := csvr.Read() // read one record
		if err != nil {
			if err == io.EOF { // normal EOF
				return badlinecount, nil
			}
			fmt.Println("Rejected CSV line: ", err.Error()) // trouble
			//  ***NEED TO CHECK FOR I/O error here***
			badlinecount++          // tally
			if badlinecount < 100 { // stop after 100 errors, for now
				continue
			} // and skip
			return badlinecount, err // I/O error
		}
		err = fn(fields, outf, outdb) // handle this record
		if err != nil {
			panic(err)
		}
	}
	panic("Unreachable") // can't get here and compiler should know it.
}

//
//  printstats -- print final statistics
//
func printstats(t tallies) {
	fmt.Printf("Record counts:\n In:  %12d\n Out: %12d\n Err: %12d\n", t.in, t.out, t.errors)
	if t.in > 0 {
		pct := (float64(t.out) * 100) / float64(t.in)
		fmt.Printf(" %1.2f%% kept.\n", pct) // percent kept
	}
}

//
//  init -- misc. initialization
//
func init() {
	const domainsuffixfile = "/home/john/projects/gocode/src/certscan/data/effective_tld_names.dat" // should be overrideable
	const caoidfile = "/home/john/projects/gocode/src/certscan/data/catypetable.csv"                // should be overrideable
	err := TLDinfo.Loadpublicsuffixlist(domainsuffixfile)                                           // load domain info
	if err != nil {
		panic(err)
	}
	err = CAinfo.Loadoidinfo(caoidfile) // load CA policy info
	if err != nil {
		panic(err)
	}
}

//
//  Main program
//
func main() {
	parseargs(&cmdopts)      // parse command line
	var csvwp *csv.Writer = nil // output csv file, if any
	var dbwriter *certumich.Certdb // output database, if any
	if len(cmdopts.outfilename) > 0 {   // open output file
		fmt.Println("Output file: ", cmdopts.outfilename)
		fo, err := os.Create(cmdopts.outfilename) // create output file
		if err != nil {
			panic(err)
		}
		defer fo.Close()         // close at exit (after flush)
		w := bufio.NewWriter(fo) // make a write buffer
		csvwp = csv.NewWriter(w) // make a CSV writer
		defer (*csvwp).Flush()   // flush at exit (before close)
	}
	//  Output database files if requested
	if cmdopts.database != "" {
	    if cmdopts.user == "" || cmdopts.pass == "" {
	        panic("-database specified, but not -user or -pass for access.")    // fails
	    }
	    var db certumich.Certdb // our database object
	    err := db.Connect(cmdopts.database, cmdopts.user, cmdopts.pass, cmdopts.verbose) 
	    if err != nil {
	        panic(err)
	    }
	    dbwriter = &db          // keeping a local beyond scope, OK in Go?
	    ////defer db.Disconnect()   // emergency disconnect at exit
	}
	//  Process all the input files
	for i := range cmdopts.infilenames {
		println("Input file: ", cmdopts.infilenames[i])
		badlinecount, err := readinputfile(cmdopts.infilenames[i], dorec, csvwp, dbwriter)
		if err != nil {
			panic(err)
		} // fail
		if badlinecount > 0 {
			fmt.Println(badlinecount, "bad CSV lines in this file.") // report problems
		}
	}
	if dbwriter != nil {
	    err := dbwriter.Disconnect() // finish database update
	    if err != nil {
	        panic(err)
	    }
	    dbwriter = nil
    }
	//  Final statistics
	printstats(tally)
}
