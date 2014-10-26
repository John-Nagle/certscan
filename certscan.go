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
//  Globals
//
var verbose bool = false // true if verbose

//
//  parseargs -- parse input args
//
//  usage: certscan [flags] [-o outfile] infile...
//
//  Returns outfilename, infilenames
//
func parseargs() (string, []string) {
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
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

type rechandler func([]string) error

//
//  dorec -- handle an input line record, already parsed into fields
//
func dorec(fields []string) error {
	interesting := false                                        // not interesting yet
	cfields := certumich.Unpackrawcert(fields)                  // convert to structure format
	altnames := cfields.X_509_subjectAltName                    // alt names
	if len(altnames) > 0 {
		///println("Alt names: ", altnames)                     // ***TEMP***
		domains, err := certumich.Unpackaltdomains(cfields)     // unpack alt names into domains
		if err != nil {                                         // pass error upward
		    fmt.Println("*** ERROR ***", err)                   // ***TEMP***
		    util.Dumpstrstruct(cfields) // dump ***TEMP***
		    ////return(nil)                                         // ***TEMP*** ignore for now
		    return(err)
		}
		if len(domains) > 0 {
		    interesting = true
		    print("Domains: ")                                  // ***TEMP***
		    for i := range domains {
			    print(" ", domains[i])
		    }
		    println()
        }

	}
	if verbose || interesting {
		util.Dumpstrstruct(cfields) // dump ***TEMP***
		fmt.Println("")
	}
	return nil
}

//
//  readinputfile -- handle an input file
//    
func readinputfile(infilename string, fn rechandler) (int, error) {
	badlinecount := 0              // no bad lines yet
	fi, err := os.Open(infilename) // open input file
	if err != nil {
		panic(err) // ***TEMP***
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
			println("Rejected line: ", err.Error()) // trouble
			//  ***NEED TO CHECK FOR I/O error here***
			badlinecount++          // tally
			if badlinecount < 100 { // stop after 100 errors, for now
				continue
			} // and skip
			return badlinecount, err // I/O error
		}
		err = fn(fields) // handle this record
		if err != nil {
			panic(err)
		}
	}
	panic("Unreachable") // can't get here and compiler should know it.
}

//
//  Main program
//
func main() {
	outfilename, infilenames := parseargs()
	println("Outfilename: ", outfilename)
	//  Process all the input files
	for i := range infilenames {
		println("Input file: ", infilenames[i])
		badlinecount, err := readinputfile(infilenames[i], dorec)
		if err != nil {
			panic(err)
		}                                                 // fail
		println(badlinecount, " bad lines in this file.") // report problems
	}
}
