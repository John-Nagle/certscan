//
//  sqlutil.go  -- utility functions for use with MySQL
//
package util

import "os"
import "bufio"
import "time"
import "fmt"
import "strings"
import "strconv"
import "regexp"
import "io/ioutil"
import "database/sql"

//
//  Conversions to the string format needed for MySQL LOAD DATA INFILE.
//
//  Format generated is:
//
const SQLFIELDSTERMINATED = ` FIELDS TERMINATED BY ',' ENCLOSED BY '"' ESCAPED BY '\\' `
const SQLQUOTE = `"`

//
//  Lines are the default: LINES TERMINATED BY '\n' STARTING BY ''
//
//  Time representation
//
const SQLDATETIME = "2006-01-02 15:04:05" // desired output format
//
//  This would be easier if MySQL accepted JSON input.
//
//  ToSQLint -- int to suitable string as SQL int.
//
func ToSQLint(s string) string {
	n, err := strconv.Atoi(s) // returns NONE if non integer
	if err != nil {
		return "NONE"
	}
	s = strconv.Itoa(n)
	return EscapeSQLfield(s)
}

//
//  ToSQLstring --  string as SQL string
//
func ToSQLstring(s string) string {
	if len(s) == 0 { // empty string is treated as NONE
		return ("NONE") // NONE without enclosing quotes - special
	}
	return EscapeSQLfield(s)
}

//
//  ToSQLbool -- bool as SQL string
//
func ToSQLbool(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "t") { // returns TRUE or FALSE in quotes
		return "\"TRUE\""
	}
	return "\"FALSE\""
}

//
//  ToSQLdatetime -- Go time to SQL datetime
//
//  Output format is 'YYYY-MM-DD HH:MM:SS'
//
func ToSQLdatetime(t time.Time) string {
	return EscapeSQLfield(t.Format(SQLDATETIME)) // format
}

//
//  ToSQLline -- combine fields into line
//
func ToSQLline(lines []string) string {
	return strings.Join(lines, ",") + "\n" // add line terminator
}

var reescape = regexp.MustCompile(`([\\\"\,\n])`) // escape ",", """, "\" with "\"
var rereplace = `\$1`                             // escape with backslash
//
//  EscapeSQLfield -- escape single SQL field
//
func EscapeSQLfield(s string) string {
	return SQLQUOTE + reescape.ReplaceAllString(s, rereplace) + SQLQUOTE
}

//
//  SQLdataloader -- support for loading data files into MySQL using LOAD DATA INFILE LOCAL
//
type SQLdataloader struct {
	fd         *os.File      // output file if any
	buf        *bufio.Writer // writer if any
	db         *sql.DB       // database handle
	reccount   int32         // number of records written in current temp file
	recmax     int32         // max records before starting a new file
	totalcount int64         // total records loaded
	loadparams string        // LOAD DATA parameters after filename
	verbose    bool          // true if verbose mode
}

//
//  doload  -- do a load operation into the database and release the temp file
//
func (d *SQLdataloader) doload() error {
	const LOADPREFIX = "LOAD DATA LOCAL INFILE '"
	const LOADSUFFIX = "' "
	if d.fd == nil { // nothing to do
		return nil
	}
	filename := d.fd.Name() // get name of file
	defer func() {
		os.Remove(filename) // delete file at end
		d.fd = nil
		d.buf = nil
	}()
	err := d.buf.Flush() // flush any remaining output
	d.buf = nil
	if err != nil {
		return err
	}
	err = d.fd.Close() // close file, file is not deleted
	d.fd = nil
	if err != nil {
		return err
	}
	cmd := LOADPREFIX + filename + LOADSUFFIX + d.loadparams // LOAD DATA command
	if d.verbose {
		fmt.Printf("Loading %d records into SQL: %s\n", d.reccount, cmd) // debug
	}
	_, err = d.db.Exec(cmd) // do the LOAD DATA command
	return (err)
}

//
//  Open -- begin a loading operation
//
//  Write does all the work.
//
func (d *SQLdataloader) Open(loadparams string, db *sql.DB, recmax int32, verbose bool) {
	if d.fd != nil {
		panic("SQL data loader Open called, already open") // program bug
	}
	d.db = db // just saves params
	d.loadparams = loadparams
	d.recmax = recmax   // records per LOAD DATA command
	d.verbose = verbose // do we want messages?
	d.reccount = 0
	d.totalcount = 0
}

//
//  Close  -- end a loading operation
//
func (d *SQLdataloader) Close() error {
	err := d.doload() // do final load and cleanup if necessary
	if err != nil {
		return err
	}
	if d.verbose {
		fmt.Printf("Successfully loaded %d records into database.\n", d.totalcount)
	}
	return (nil)
}

//
//  Write -- write a string
//
func (d *SQLdataloader) Write(s string) error {
	var err error               // needed on multiple paths
	if d.reccount >= d.recmax { // if enough recs for a LOAD DATA
		err = d.doload() // load the data into the database
		if err != nil {
			return err
		}
	} // do it
	if d.fd == nil { // if need to start a file
		d.fd, err = ioutil.TempFile("", "SQLBULKLOAD")
		if err != nil {
			return err
		}
		d.buf = bufio.NewWriter(d.fd)                   // create a new buffered writer
		d.totalcount = d.totalcount + int64(d.reccount) // tally
		d.reccount = 0                                  // it's empty
	}
	_, err = d.buf.WriteString(s) // write the string to the file
	d.reccount++                  // tally
	return err                    // return status
}
