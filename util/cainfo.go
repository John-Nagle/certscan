//
//  cainfo.go -- Certificate Authority information
//
//  
//
//  John Nagle
//  SiteTruth
//  October, 2014
//
package util

//
import "os"
import "io"
import "bufio"
import "fmt"
import "strings"
import "regexp"
import "encoding/csv"

//
//  PolicyInfo -  for one policy OID
//
type Policyinfo struct {
	Policy string // "DV", "OV", or "EV"
	CAname string // name of CA
}

//
//  CApolicyinfo -- collect info about CAs
// 
type CApolicyinfo struct {
	PolicyOID map[string]Policyinfo // policy lookup
}

//
//  parseoids -- parse OIDs from a string
//
var reoid = regexp.MustCompile(`^(\d+\.)+\d+$`) // form n.n.n with at least 2 numbers.
func parseoids(s string) []string {
	oids := make([]string, 0, 3) // accum OIDs here
	items := strings.Fields(s)   // just split on whitespace, then recognize OIDS
	for i := range items {
		match := reoid.FindString(items[i]) // match OID pattern
		if match != "" {                    // if found OID
			oids = append(oids, match) // keep it
		}
		////fmt.Printf("OID: '%s' -> %s\n", items[i], match) // ***TEMP***
	}
	return (oids)
}

//
//  addoids -- add list of OIDs to CApolicyinfo
//
func (c *CApolicyinfo) addoids(caname string, policytype string, oids []string) {
	for i := range oids {
		var pol Policyinfo
		pol.Policy = policytype
		pol.CAname = caname
		c.PolicyOID[oids[i]] = pol
	}
}

//
//  loadline  -- load one line of policy info
//
//  Ignores any non-OID info
//
func (c *CApolicyinfo) loadline(fields []string) {
	if len(fields) < 4 { // not enough fields
		return
	}
	caname := fields[0]
	c.addoids(caname, "DV", parseoids(fields[1])) // add DV oids
	c.addoids(caname, "OV", parseoids(fields[2])) // add DV oids
	c.addoids(caname, "EV", parseoids(fields[3])) // add DV oids
}

//
//  Loadoidinfo -- load policy info from our CSV file
//
//  Takes in a CSV file of certification authorities.
//  Format is: CA name, DV OIDs, OV OIDs, EV OIDs, CPS URL, Notes
//
//  OID fields may contain multiple OIDs, and non-OID text.
//
func (c *CApolicyinfo) Loadoidinfo(infilename string) error {
	fi, err := os.Open(infilename) // open input file
	if err != nil {
		return err
	}
	defer func() { // handle close
		if err := fi.Close(); err != nil {
			panic(err) // failed close is legit panic
		}
	}()
	r := bufio.NewReader(fi) // make a read buffer
	csvr := csv.NewReader(r) // make a CSV reader
	//  Set any CSV format parameters here if necessary.
	csvr.TrailingComma = true // allow trailing comma (deprecated)
	//  Create map for results.  Only save map if success.
	c.PolicyOID = make(map[string]Policyinfo) // working info
	//  Read the file
	for { // until EOF
		fields, err := csvr.Read() // read one record
		if err != nil {
			if err == io.EOF {
				break
			} else {
				c.PolicyOID = nil
				return err
			}
		}
		c.loadline(fields) // load one line from file
	}
	return nil // normal return
}

//
//  Dump -- dump for debug
//
func (c *CApolicyinfo) Dump() {
	fmt.Println("CA Policy info:")
	if c.PolicyOID == nil {
		fmt.Println("  Not loaded.")
		return
	}
	for k, v := range c.PolicyOID { // read out map
		fmt.Printf("  Policy: %s.  OID: '%s'  CA name: %s\n", v.Policy, k, v.CAname)
	}
	fmt.Println("")
}
