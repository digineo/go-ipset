// Package ipset contains bindings to libipset
// Requirements: apt install ipset-dev
package ipset

import (
	"fmt"
	"os"
	"unsafe"
)

/*
#cgo pkg-config: libipset

#include <string.h>
#include <stdlib.h>
#include <libipset/data.h>
#include <libipset/parse.h>
#include <libipset/session.h>
#include <libipset/types.h>

// Returns the ipset_arg with the given name
const struct ipset_arg*
get_ipset_arg(struct ipset_type *type, const char *argname){
  const struct ipset_arg *arg;

  for (arg = type->args[IPSET_ADD]; arg->opt; arg++) {
    if (strcmp(argname, arg->name[0]) == 0){
      return arg;
    }
  }
  return NULL;
}

*/
import "C"

func init() {
	C.ipset_load_types()
}

// Add adds a new entry to an existing set
func Add(setname, address string, args ...string) error {
	return exec(C.IPSET_CMD_ADD, setname, address, args...)
}

// Del deletes an entry from an existing set
func Del(setname, address string, args ...string) error {
	return exec(C.IPSET_CMD_DEL, setname, address, args...)
}

func exec(cmd uint32, setname, address string, args ...string) error {
	if len(args)%2 != 0 {
		return fmt.Errorf("odd number of arguments given")
	}

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
