//
//  dumpstruct.go  -- dump a structure
//
//  Uses reflection.  Slow, for debug.
//
package util

import "fmt"
import "reflect"

//
//  Dumpstrstruct -- dump a structure of strings in field order.
//
func Dumpstrstruct(r interface{}) {
	t := reflect.TypeOf(r)        // type of object to dump
	v := reflect.ValueOf(r)         // values of object to dump
	for i := 0; i < t.NumField(); i++ { // for all fields
		finfo := t.Field(i)                                  // field info for field
		fmt.Printf(" #%2d: (%s)  %s\n", i, finfo.Name, v.Field(i).String()) // print field
	}
}
