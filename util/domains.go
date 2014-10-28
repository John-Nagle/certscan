//
//  domains.go -- utilities for working with domain names
//
//
//  John Nagle
//  SiteTruth
//  October, 2014
//
package util

import "strings"
import "os"
import "io"
import "bufio"
import "regexp"
import "errors"

//
//  Issubdomain  -- true if a is subdomain of b.
//
//  Also true for same domain.
//
func Issubdomain(a string, b string) bool {
	al := len(a)
	bl := len(b)
	headlen := al - bl                           // subdomain extra bytes
	if (al == 0) || (bl == 0) || (headlen < 0) { // b must not be longer than a, of course.
		return false
	}
	a = strings.ToLower(a) // compare in lower case
	b = strings.ToLower(b)
	return (a == b) || (strings.HasSuffix(a, b) && strings.HasSuffix(a[:headlen], ".")) // right substring, and remainder must end with "."
}

//
//  Loadpublicsuffixlist  -- load list of public domain suffixes
//
//  This comes from "https://publicsuffix.org/list/effective_tld_names.dat"
//
func Loadpublicsuffixlist(infile string) ([]string, error) {
	const icannstart = "===BEGIN ICANN DOMAINS==="
	const icannend = "===END ICANN DOMAINS==="
	redelim := regexp.MustCompile(`===.+===`) // get section delimiter, of form "===DELIM==="
	suffixes := make([]string, 100)           // rough size of list today
	//  Read the file
	fi, err := os.Open(infile) // open file of public domain suffixes
	if err != nil {
		return suffixes, err // Unable to open input, fail
	}
	defer func() { // handle close
		if err := fi.Close(); err != nil {
			panic(err) // failed close is legit panic
		}
	}()
	r := bufio.NewReader(fi) // make a read buffer
	inicann := false         // not in ICANN block yet
	for {                    // until EOF
		s, err := r.ReadString('\n') // read a line
		if err != nil {              // EOF or error
			if err == io.EOF { // if EOF
				break // done
			}
			return suffixes, err // I/O error
		}
		s = strings.TrimSpace(s) // clean line
		if len(s) == 0 {         // ignore blank lines
			continue
		}
		if strings.HasPrefix(s, "//") { // search for delim
			found := redelim.Find([]byte(s)) // matches "===ANYTHING==="
			if len(found) > 0 {              // if found something
				delim := string(found[:]) // delimiter as string
				switch {
				case delim == icannstart: // if entering ICANN block
					inicann = true
					break
				case delim == icannend: // if leaving ICANN block
					inicann = false
					break
				}
			}
		} else { // non-comment
			if inicann { // save ICANN names only
				//  ***SHOULD VALIDATE DOMAIN SYNTAX HERE***
				suffixes = append(suffixes, s) // add to domain suffixes
			}
		}
	}
	// finish up
	if len(suffixes) < 1 { // did not find any domains
		return suffixes, errors.New("No domain suffixes in suffix file: " + infile) // must be bogus file
	}
	return suffixes, nil // normal return
}
