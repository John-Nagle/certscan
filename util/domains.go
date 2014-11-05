//
//  domains.go -- utilities for working with domain names
//
//
//  John Nagle
//  SiteTruth
//  October, 2014
//
package util

import "fmt"
import "strings"
import "os"
import "io"
import "bufio"
import "regexp"
import "errors"
import "code.google.com/p/go.net/idna"

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
//  DomainSuffixes -- public domain name suffixes and lookup utilities for them
//
type DomainSuffixes struct {
	reversedsuffixes map[string]bool // suffixes, reversed. Set.
}

//
//  Reversedomain  -- turn a.b.c into c.b.a
//
func Reversedomain(s string) string {
	parts := strings.Split(s, ".") // split into parts
	nparts := len(parts)           // in-place reverse        
	for i := 0; i < nparts/2; i++ {
		tmp := parts[nparts-i-1] // swap
		parts[nparts-i-1] = parts[i]
		parts[i] = tmp
	}
	return strings.Join(parts, ".") // return as string       
}

//
//  Samesecondleveldomain -- true if two domains have the same second level domain
//
func (d *DomainSuffixes) Samesecondleveldomain(a string, b string) (bool, bool) {
	_, a2nd, atld, aok := d.Domainparts(a) // break apart domain
	_, b2nd, btld, bok := d.Domainparts(b)
	return (atld == btld) && (a2nd == b2nd), aok && bok // return true if matched
}

//
//  Domainparts  -- break up domain name into public TLD, 2nd level domain, and local subdomain
//
//  "sub.example.com" is broken into local subdomain "sub", 2nd level domain "example", and TLD "com"
//
//  The list of public TLDs is used for this purpose.
//
func (d *DomainSuffixes) Domainparts(s string) (string, string, string, bool) {
	if d.reversedsuffixes == nil {
		panic("DomainSuffixes not loaded")
	}
	parts := strings.Split(s, ".")    // domain parts
	for i := 0; i < len(parts); i++ { // finding longest TLD that matches
		tld := strings.Join(parts[i:], ".")         // candidate TLD
		if d.reversedsuffixes[Reversedomain(tld)] { // if matched TLD
			switch {
			case i == 0:
				return "", "", tld, false // this is a TLD - it has no 2nd
			case i == 1:
				return "", parts[0], tld, true // second level domain
			default:
				return strings.Join(parts[0:i-1], "."), parts[i-1], tld, true // sub, 2nd, tld, OK
			}
		}
	}
	return "", "", "", false // no TLD match
}

//
//  Loadpublicsuffixlist  -- load list of public domain suffixes
//
//  This comes from "https://publicsuffix.org/list/effective_tld_names.dat"
//
func (d *DomainSuffixes) Loadpublicsuffixlist(infile string) error {
	const icannstart = "===BEGIN ICANN DOMAINS==="
	const icannend = "===END ICANN DOMAINS==="
	redelim := regexp.MustCompile(`===.+===`) // get section delimiter, of form "===DELIM==="
	//  Read the file
	fi, err := os.Open(infile) // open file of public domain suffixes
	if err != nil {
		return err // Unable to open input, fail
	}
	defer func() { // handle close
		if err := fi.Close(); err != nil {
			panic(err) // failed close is legit panic
		}
	}()
	d.reversedsuffixes = make(map[string]bool) // suffix set - value always true
	r := bufio.NewReader(fi)                   // make a read buffer
	inicann := false                           // not in ICANN block yet
	for {                                      // until EOF
		s, err := r.ReadString('\n') // read a line
		if err != nil {              // EOF or error
			if err == io.EOF { // if EOF
				break // done
			}
			return err // I/O error
		}
		s = strings.TrimSpace(s) // clean line
		if len(s) == 0 {         // ignore blank lines
			continue
		}
		if strings.HasPrefix(s, "//") { // if comment, which includes section delim
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
				domain, err := idna.ToUnicode(s)    // all Unicode, no punycode
				if err != nil {
				    return err
				}
				d.reversedsuffixes[Reversedomain(domain)] = true // add to domain suffixes
			}
		}
	}
	// finish up
	if len(d.reversedsuffixes) < 1 { // did not find any domains
		d.reversedsuffixes = nil                                          // no map
		return errors.New("No domain suffixes in suffix file: " + infile) // must be bogus file
	}
	return nil // normal return
}

//
//  Dump -- dump state of this object for debug
//
func (d *DomainSuffixes) Dump() {
	fmt.Printf("Domain suffixes. Loaded=%t.\n", d.reversedsuffixes != nil) // dump to standard output
	if d.reversedsuffixes != nil {
		fmt.Printf(" %d domain suffixes:\n", len(d.reversedsuffixes))
		for key, _ := range d.reversedsuffixes {
			fmt.Printf("  '%s'\n", key)
		}
	}
}
