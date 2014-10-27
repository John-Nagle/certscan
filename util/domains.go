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

//
//  Issubdomain  -- true if a is subdomain of b.
//
//  Also true for same domain.
//
func Issubdomain(a string, b string) bool {
	headlen := len(a) - len(b) // subdomain extra bytes
	if headlen < 0 {           // b must not be longer than a, of course.
		return false
	}
	a = strings.ToLower(a) // compare in lower case
	b = strings.ToLower(b)
	return (a == b) || (strings.HasSuffix(a, b) && strings.HasSuffix(a[:headlen], ".")) // right substring, and remainder must end with "."
}
