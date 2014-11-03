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

////import "strings"
import "os"
import "io"
import "bufio"
import "certscan/certumich"
import "certscan/util"

//
//  keepoptions -- exclude record if lacks any of these properties.
//
//  Default is exclude, options override.
//
type keepoptions struct {
	altname      bool   // lacks alt domain names
	org          bool   // lacks Organization (O) field
	valid        bool   // not valid cert
	browservalid bool   // not valid cert for any known browser cert chain
	casigned     bool   // CA (not self-signed) cert
	policy       string // Keep record only if policy matches ('DV', 'OV', 'EV', or an OID value)
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
var verbose bool = false        // true if verbose
var keepopts keepoptions        // the keep/exclude options
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
func parseargs() (string, []string) {
	//  Command line options
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.BoolVar(&keepopts.altname, "noaltname", false, "Keep record if no Alt Names")
	flag.BoolVar(&keepopts.org, "noorg", false, "Keep record if no Organization")
	flag.BoolVar(&keepopts.valid, "novalid", false, "Keep record if not valid cert")
	flag.BoolVar(&keepopts.browservalid, "nobrowservalid", false, "Keep record if not valid per Mozilla root cert list")
	flag.BoolVar(&keepopts.casigned, "nocasigned", false, "Keep record if not CA-signed (self-signed cert)")
	flag.StringVar(&keepopts.policy, "policy", "", "Keep record if policy matches ('DV', 'OV', 'EV', or an OID value)")
	var outfilename string
	infilenames := make([]string, 0)
	flag.StringVar(&outfilename, "o", "", "Output file (csv format)")
	flag.Parse() // parse command line
	if verbose { // dump args if verbose
		fmt.Println("Verbose mode.")
		fmt.Print("Output file: ", outfilename, "\n")
		fmt.Println("Input files: ")
		for i := range flag.Args() {
			fmt.Println(flag.Arg(i))
		}
	} // return infiles as array of strings
	for i := range flag.Args() {
		infilenames = append(infilenames, flag.Arg(i))
	}
	return outfilename, infilenames
}

type rechandler func([]string, *csv.Writer) error

//
//  keeptest -- do we want to keep this record?
//
func keeptest(cfields certumich.Processedcert) (bool, error) {
	keep := true // assume keep
	//  Valid flags check
	keep = keep && (keepopts.valid || cfields.Valid)               // discard if not valid
	keep = keep && (keepopts.browservalid || cfields.Browservalid) // discard if not big-name browser valid
	keep = keep && (keepopts.casigned || cfields.CAsigned)         // discard if self-signed
	//  Unpack subject info
	domain := cfields.Commonname // Common Name, i.e. main domain
	//
	//  CA Policy check
	//
	if keep && keepopts.policy != "" {
		////fmt.Printf("'%s' policies:", domain)
		find := false
		for i := range cfields.Policies { // for all fields
			field := cfields.Policies[i]
			keep = keep || keepopts.policy == field   // if it matches an actual policy OID
			policyitem, ok := CAinfo.Getpolicy(field) // look up policy item
			if ok {
				fmt.Printf("Domain '%s' OID %s (%s) from CA %s\n", domain, field, policyitem.Policy, policyitem.CAname) // ***TEMP***
				find = find || policyitem.Policy == keepopts.policy                                                     // keep if policy matches policy param
			}
		}
		keep = keep && find // don't keep unless find
	}
	//  Alt names check  
	if keep && !keepopts.altname { // if requiring alt names
		if len(cfields.Domains2ld) > 1 { // if multiple domain cert
			keep = true
			fmt.Printf("Multiple-domain cert: '%s' vs '%s'\n", cfields.Domains2ld[0], cfields.Domains2ld[1]) // ***TEMP***
		}
	}
	//  Has Organization field check
	if keep && !keepopts.org {
		foundorg := cfields.Organization != "" // test for presence of org
		keep = keep && foundorg                // must have Organization field
	}
	return keep, nil // final result
}

//
//  dorec -- handle an input line record, already parsed into fields
//
func dorec(fields []string, outf *csv.Writer) error {
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
	if (outf != nil) && keep { // if output file
		err := (*outf).Write(fields) // write output
		tally.out++                  // count out
		if err != nil {
			panic(err) // fails
		}
	}
	if verbose {
		cfields.Dump()
	}
	return nil
}

//
//  readinputfile -- handle an input file
//    
func readinputfile(infilename string, fn rechandler, outf *csv.Writer) (int, error) {
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
		err = fn(fields, outf) // handle this record
		if err != nil {
			panic(err)
		}
	}
	panic("Unreachable") // can't get here and compiler should know it.
}

//
//  printstats-- print final statistics
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
	outfilename, infilenames := parseargs()
	var csvwp *csv.Writer = nil // output csv file, if any
	if len(outfilename) > 0 {   // open output file
		fmt.Println("Output file: ", outfilename)
		fo, err := os.Create(outfilename) // create output file
		if err != nil {
			panic(err)
		}
		defer fo.Close()         // close at exit (after flush)
		w := bufio.NewWriter(fo) // make a write buffer
		csvwp = csv.NewWriter(w) // make a CSV writer
		defer (*csvwp).Flush()   // flush at exit (before close)
	}
	//  Process all the input files
	for i := range infilenames {
		println("Input file: ", infilenames[i])
		badlinecount, err := readinputfile(infilenames[i], dorec, csvwp)
		if err != nil {
			panic(err)
		} // fail
		if badlinecount > 0 {
			fmt.Println(badlinecount, "bad CSV lines in this file.") // report problems
		}
	}
	//  Final statistics
	printstats(tally)
}
