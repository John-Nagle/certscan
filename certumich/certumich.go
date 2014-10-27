//
//  certumich -- utilities for working with U_Michigan SSL certificate files
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

import "strings"
import "errors"

//
//  Constants
//
const Fieldcount = 44 // there are 44 fields in these records

//
//  Rawcertumich --  the 44 fields of a U_Mich CSV record, as strings
//
//  Ref: https://scans_io/data/umich/https/schema_txt
//
type Rawcert struct {
	Certificate_id                   string
	Hex_encoded_SHA_1_fingerprint    string
	Serial_number                    string
	Issuer_id                        string
	Version                          string
	Subject                          string
	Issuer                           string
	Is_ca                            string
	Is_self_signed                   string
	Not_valid_before                 string
	Not_valid_after                  string
	Is_valid                         string
	OpenSSL_validation_error         string
	Is_ubuntu_valid                  string
	Is_mozilla_valid                 string
	Is_windows_valid                 string
	Is_apple_valid                   string
	X_509_basicConstraints           string
	X_509_crlDistributionPoints      string
	X_509_extendedKeyUsageidentifier string
	X_509_authorityKeyIdentifier     string
	X_509_subjectKeyIdentifier       string
	X_509_keyUsage                   string
	X_509_certificatePolicies        string
	X_509_authorityInfoAccess        string
	X_509_subjectAltName             string
	X_509_nsCertType                 string
	X_509_nsComment                  string
	X_509_policyConstraints          string
	X_509_privateKeyUsagePeriod      string
	X_509_SMIME_CAPS                 string
	X_509_issuerAltName              string
	Signature_algo                   string
	Depth                            string
	Public_key_id                    string
	First_seen_at                    string
	Public_key_type                  string
	In_ubuntu_root_store             string
	In_mozilla_root_store            string
	In_windows_root_store            string
	In_apple_root_store              string
	Is_revoked                       string
	Revoked_at                       string
	Reason_revoked                   string
}

//
//  NameValue -- Name/value tuple, for general use
//
type NameValue struct {
	Name  string // name
	Value string // value
}

//
//  Unpackrawcert -- unpack into named fields
//
//  Input must be an array of 44 strings.
//
func Unpackrawcert(s []string) Rawcert {
	var r Rawcert
	r.Certificate_id = s[0]
	r.Hex_encoded_SHA_1_fingerprint = s[1]
	r.Serial_number = s[2]
	r.Issuer_id = s[3]
	r.Version = s[4]
	r.Subject = s[5]
	r.Issuer = s[6]
	r.Is_ca = s[7]
	r.Is_self_signed = s[8]
	r.Not_valid_before = s[9]
	r.Not_valid_after = s[10]
	r.Is_valid = s[11]
	r.OpenSSL_validation_error = s[12]
	r.Is_ubuntu_valid = s[13]
	r.Is_mozilla_valid = s[14]
	r.Is_windows_valid = s[15]
	r.Is_apple_valid = s[16]
	r.X_509_basicConstraints = s[17]
	r.X_509_crlDistributionPoints = s[18]
	r.X_509_extendedKeyUsageidentifier = s[19]
	r.X_509_authorityKeyIdentifier = s[20]
	r.X_509_subjectKeyIdentifier = s[21]
	r.X_509_keyUsage = s[22]
	r.X_509_certificatePolicies = s[23]
	r.X_509_authorityInfoAccess = s[24]
	r.X_509_subjectAltName = s[25]
	r.X_509_nsCertType = s[26]
	r.X_509_nsComment = s[27]
	r.X_509_policyConstraints = s[28]
	r.X_509_privateKeyUsagePeriod = s[29]
	r.X_509_SMIME_CAPS = s[30]
	r.X_509_issuerAltName = s[31]
	r.Signature_algo = s[32]
	r.Depth = s[33]
	r.Public_key_id = s[34]
	r.First_seen_at = s[35]
	r.Public_key_type = s[36]
	r.In_ubuntu_root_store = s[37]
	r.In_mozilla_root_store = s[38]
	r.In_windows_root_store = s[39]
	r.In_apple_root_store = s[40]
	r.Is_revoked = s[41]
	r.Revoked_at = s[42]
	r.Reason_revoked = s[43]
	return r
}

//
//  Unpackaltdomains  -- unpack alt names field
//
//  Returns domains ("DNS") only.  No emails, etc.
//
func Unpackaltdomains(cfields Rawcert) ([]string, error) {
	subjectaltnames := strings.TrimSpace(cfields.X_509_subjectAltName) // get subject alt name field
	if len(subjectaltnames) < 1 || subjectaltnames == "<EMPTY>" {      // if none, return empty string
		var empty []string // empty array of strings
		return empty, nil  // isn't garbage collection convenient?
	}
	//  Have data of form "type:value, type:value"
	pairs := strings.Split(subjectaltnames, ",") // split into tuples
	domains := make([]string, 0, 10)             // make space for an array of strings
	for i := range pairs {                       // iterate over pairs
		pair := pairs[i]                          // this pair
		typevalue := strings.SplitN(pair, ":", 2) // split at first ":" (IPv6 addresses have ":" in them)
		if len(typevalue) != 2 {                  // should always be 2
			var empty []string // empty array of strings
			return empty, errors.New("Unexpected text in alt domain field: '" + subjectaltnames + "'")
		}
		typepart := strings.TrimSpace(typevalue[0])
		domain := strings.TrimSpace(typevalue[1])
		if typepart == "DNS" || typepart == "dns" {
			domains = append(domains, domain) // add to 
		}
	}
	return domains, nil // normal return
}

type KeyValueMap map[string]string // a key/value map
//  
//  addparamtomap - break "X=Y" form into name, value and add to map.
//
func addparamtomap(d KeyValueMap, field string) error {
	field = strings.TrimSpace(field) // clean up string
	if len(field) < 1 {              // ignore empty fields
		return nil
	}
	keyandvalue := strings.SplitN(field, "=", 2)
	if (len(keyandvalue) != 2) || (len(keyandvalue[0]) < 1) {
		msg := "Invalid NAME=value syntax in certificate file: " + field
		return errors.New(msg)
	}
	d[strings.TrimSpace(keyandvalue[0])] = strings.TrimSpace(keyandvalue[1])
	return nil
}

//
//  Unpackparamfields -- unpack fields of form name=value, name=value...
//
//  Unfortunately, the "value" fields may contain commas. So this is a parsing headache.
//
func Unpackparamfields(s string) (KeyValueMap, error) {
	////println("Param fields: ",s)                     // ***TEMP***
	d := make(KeyValueMap, 10)      // returned key/value pairs.
	fields := strings.Split(s, ",") // split at comma
	var workfield string = ""       // last field if left over
	for i := range fields {
		if strings.ContainsRune(fields[i], '=') { // if it has an "="
			err := addparamtomap(d, workfield) // do previous field
			if err != nil {
				return d, err
			}
			workfield = fields[i] // new work field
		} else { // is part of previous expression
			workfield = workfield + "," + fields[i]
		}
	}
	err := addparamtomap(d, workfield)
	return d, err
}

//
//  Seterror -- set an error message into the array of fields for later use
//
//  Put in the field OpenSSL_validation_error
//
func Seterror(fields []string, msg string) {
	const ERRFIELD = 12 // goes into field 12
	if len(strings.TrimSpace(fields[ERRFIELD])) == 0 {
		fields[ERRFIELD] = "***ERROR*** " + msg // put msg in record if no other error
	}
}
