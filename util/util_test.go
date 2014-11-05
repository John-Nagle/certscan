//
//  util_test.go  -- tests for utility functions
//
//  John Nagle
//  SiteTruth
//  November, 2014
//
//  License for this file: LGPL.
//
package util
import "time"
import "testing"
//
//  Testsqlesape -- test SQL escaping
//
func TestTLDinfo(t *testing.T) {
    const TESTRESULT = "\"TRUE\",\"123\",\" Now\\, \\\"think\\\"\\\nLine 2.\",\"2001-09-11 10:45:00\""
    ////const TESTRESULT = "Received: \"TRUE\",\"123\",\" Now, " // Line 2.\",\"2001-09-11 10:45:00\""
    const TESTTIMESTR = "2001-09-11 10:45:00"
    const fieldcnt = 4
    fields := make([]string, fieldcnt, fieldcnt)
    fields[0] = ToSQLbool("TRUE")
    fields[1] = ToSQLint("123")
    fields[2] = ToSQLstring(" Now, \"think\"\nLine 2.")
    testtime, _ := time.Parse(SQLDATETIME, TESTTIMESTR)
    fields[3] = ToSQLdatetime(testtime)
    line := ToSQLline(fields)
    if line != TESTRESULT {
        t.Logf("SQL escaping FAIL: ")
		t.Logf(" Expected: " + TESTRESULT)
		t.Logf(" Received: " + line)
		t.FailNow()
	}
}
