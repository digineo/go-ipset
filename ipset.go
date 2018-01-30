// Package ipset contains bindings to libipset
// Requirements: apt install ipset-dev
package ipset

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sync"
	"unsafe"
)

/*
#cgo pkg-config: libipset
#include <stdlib.h>
#include "ipset.h"
*/
import "C"

// ListResult is the result of a LIST command
type ListResult struct {
	Sets []IPSet `xml:"ipset"`
}

// IPSet represents a returned ipset
type IPSet struct {
	Type     string   `xml:"type"`
	Revision byte     `xml:"revision"`
	Name     string   `xml:"name,attr"`
	Header   Header   `xml:"header"`
	Members  []Member `xml:"members>member"`
}

// Header is the header of an ipset result
type Header struct {
	Family     string `xml:"family"`
	HashSize   int    `xml:"hashsize"`
	MaxElem    int    `xml:"maxelem"`
	Timeout    int    `xml:"timeout"`
	MemSize    int    `xml:"memsize"`
	References int    `xml:"references"`
	NumEntries int    `xml:"numentries"`
}

// Member is the entry of an ipset
type Member struct {
	Elem    string `xml:"elem"`
	Timeout int    `xml:"timeout"`
}

var (
	xmlWriter *io.PipeWriter
	listLock  sync.Mutex
)

func init() {
	C.ipset_load_types()
}

//export outfn
func outfn(buf *C.char) {
	xmlWriter.Write([]byte(C.GoString(buf)))
}

// ListAll returns all ipsets
func ListAll() ([]IPSet, error) {
	return list("")
}

// List returns a single ipset
func List(setname string) (*IPSet, error) {
	list, err := list(setname)
	if err != nil {
		return nil, err
	}
	return &list[0], nil
}

func list(setname string) ([]IPSet, error) {
	// Create session
	session := C.session_init_xml()
	if session == nil {
		return nil, fmt.Errorf("failed to initialize ipset session")
	}
	defer C.ipset_session_fini(session)

	listLock.Lock()
	defer listLock.Unlock()

	var reader *io.PipeReader
	var result ListResult
	var err error
	var wg sync.WaitGroup
	reader, xmlWriter = io.Pipe()

	wg.Add(1)
	go func() {
		err = xml.NewDecoder(reader).Decode(&result)
		wg.Done()
	}()

	if setname != "" {
		cSetname := C.CString(setname)
		defer C.free(unsafe.Pointer(cSetname))

		// Set setname
		if C.ipset_parse_setname(session, C.IPSET_SETNAME, cSetname) != 0 {
			return nil, fmt.Errorf("failed to parse setname '%s'", setname)
		}
	}

	// Finally execute the command
	if retval := C.ipset_cmd(session, C.IPSET_CMD_LIST, 0); retval != 0 {
		return nil, fmt.Errorf("ipset failed with %d", retval)
	}

	xmlWriter.Close()
	xmlWriter = nil
	wg.Wait()

	return result.Sets, nil
}

// Add adds a new entry to an existing set
func Add(setname, address string, args ...string) error {
	return exec(C.IPSET_CMD_ADD, setname, address, args...)
}

// Del deletes an entry from an existing set
func Del(setname, address string, args ...string) error {
	return exec(C.IPSET_CMD_DEL, setname, address, args...)
}

// Test an entry from an existing set
func Test(setname, address string, args ...string) error {
	return exec(C.IPSET_CMD_TEST, setname, address, args...)
}

func exec(cmd uint32, setname, address string, args ...string) error {
	if len(args)%2 != 0 {
		return fmt.Errorf("odd number of arguments given")
	}

	listLock.Lock()
	defer listLock.Unlock()

	cAddress := C.CString(address)
	defer C.free(unsafe.Pointer(cAddress))
	cSetname := C.CString(setname)
	defer C.free(unsafe.Pointer(cSetname))

	// Create session
	session := C.ipset_session_init(nil)
	if session == nil {
		return fmt.Errorf("failed to initialize ipset session")
	}
	defer C.ipset_session_fini(session)

	// Replace existing entries
	C.ipset_envopt_parse(session, C.IPSET_ENV_EXIST, nil)

	// Set setname
	if C.ipset_parse_setname(session, C.IPSET_SETNAME, cSetname) != 0 {
		return fmt.Errorf("failed to parse setname '%s'", setname)
	}

	// Get type
	typ := C.ipset_type_get(session, cmd)
	if typ == nil {
		if os.Geteuid() != 0 {
			return fmt.Errorf("failed to get type of cmd %d - not running as root", cmd)
		}
		return fmt.Errorf("failed to get type of cmd %d", cmd)
	}
	C.ipset_parse_elem(session, typ.last_elem_optional, cAddress)

	// Iterate over argument pairs
	for i := 0; i < len(args); i += 2 {
		key := args[i]
		val := args[i+1]
		cKey := C.CString(key)
		cVal := C.CString(val)
		defer C.free(unsafe.Pointer(cKey))
		defer C.free(unsafe.Pointer(cVal))

		if arg := C.get_ipset_arg(typ, cKey); arg != nil {
			if retval := C.ipset_call_parser(session, arg, cVal); retval != 0 {
				return fmt.Errorf("failed to set %s=%s (%d)", key, val, retval)
			}
		} else {
			return fmt.Errorf("unknown argument: %s", key)
		}
	}

	// Finally execute the command
	if retval := C.ipset_cmd(session, cmd, 0); retval != 0 {
		return fmt.Errorf("ipset failed with %d", retval)
	}

	return nil
}
