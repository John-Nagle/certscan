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
import "strings"
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
	altname      bool // lacks alt domain names
	org          bool // lacks Organization (O) field
	valid        bool // not valid cert
	browservalid bool // not valid cert for any known browser cert chain
	casigned     bool // CA (not self-signed) cert
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
func keeptest(cfields certumich.Rawcert) (bool, error) {
	keep := true // assume keep
	//  Valid flags check
	keep = keep && (keepopts.valid || strings.HasPrefix("t", cfields.Is_valid)) // discard if not valid
	keep = keep && (keepopts.browservalid ||
		strings.HasPrefix("t", cfields.Is_mozilla_valid) ||
		strings.HasPrefix("t", cfields.Is_windows_valid) ||
		strings.HasPrefix("t", cfields.Is_apple_valid)) // discard if not big-name browser valid
	keep = keep && (keepopts.casigned || !strings.HasPrefix("t", cfields.Is_self_signed)) // discard if self-signed
	//  Unpack subject info
	subjectparams, err := certumich.Unpackparamfields(cfields.Subject) // unpack Subject field
	if err != nil {
		return false, err // pass error upward
	}
	domain := subjectparams["CN"] // Common Name, i.e. main domain
	//  Alt names check  
	if keep && !keepopts.altname { // if requiring alt names
		altnames := cfields.X_509_subjectAltName // alt names
		if len(altnames) == 0 {
			keep = false
		} else {
			domains, err := certumich.Unpackaltdomains(cfields) // unpack alt names into domains
			if err != nil {
				return false, err // pass error upward
			}
			if domain != "" {
				domains = append(domains, domain) // add common name to domains
			}
			if len(domains) == 0 { // have domains
				keep = false
			} else { // check if subdomains of main name		
				keep = false
				dtld := ""               // no top-level domain yet
				d2nd := ""               // no second-level domain yet
				for i := range domains { // for all domains
					_, a2nd, atld, aok := TLDinfo.Domainparts(domains[i]) // break apart domain
					if !aok {                                             // skip any non-domain junk
						continue
					}
					if dtld == "" { // if first TLD found
						dtld = atld
						d2nd = a2nd
					} else {
						if (atld != dtld) || (a2nd != d2nd) { // if different tld or 2ld
							fmt.Printf("Multiple-domain cert: '%s.%s' vs '%s.%s'\n", a2nd, atld, d2nd, dtld) // ***TEMP***
							keep = true
							break
						}
					}
				}
			}
		}
	}
	//  Has Organization field check
	if keep && !keepopts.org {
		org, foundorg := subjectparams["O"] // test for presence of org
		if org == subjectparams["CN"] {     // if org is same as the domain name
			foundorg = false // org not meaningful, ignore
		}
		keep = keep && foundorg // must have Organization field
	}
	return keep, nil // final result
}

//
//  dorec -- handle an input line record, already parsed into fields
//
func dorec(fields []string, outf *csv.Writer) error {
	tally.in++                                 // count in
	cfields := certumich.Unpackrawcert(fields) // convert to structure format
	keep, err := keeptest(cfields)             // keep this record?
	if err != nil {                            // trouble
		msg := "INVALID RECORD FORMAT: " + err.Error() // create message
		certumich.Seterror(fields, msg)                // set in record for later use
		tally.errors++                                 // count errors
		keep = true                                    // force keep
	}
	if (outf != nil) && keep { // if output file
		err := (*outf).Write(fields) // write output
		tally.out++                  // count out
		if err != nil {
			panic(err) // fails
		}
	}
	if verbose {
		subjectparams, err := certumich.Unpackparamfields(cfields.Subject) // unpack Subject field
		if err != nil {
			fmt.Printf("Subject field syntax incorrect: %s\n", cfields.Subject)
		} else {
			cn := subjectparams["CN"]
			cnsub, cn2nd, cntld, cnok := TLDinfo.Domainparts(cn)
			fmt.Printf("CN: '%s'  TLD: '%s'  2LD: '%s'  Subdomain: '%s'  (Valid TLD: %t)\n", cn, cntld, cn2nd, cnsub, cnok)
		}
		util.Dumpstrstruct(cfields) // dump ***TEMP***
		fmt.Printf("\n")
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
	err := TLDinfo.Loadpublicsuffixlist(domainsuffixfile)                                           // load list
	if err != nil {
		panic(err)
	}
	err = CAinfo.Loadoidinfo(caoidfile) // load list
	if err != nil {
		panic(err)
	}

	////TLDinfo.Dump()                                                                      // ***TEMP***
	CAinfo.Dump()
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
