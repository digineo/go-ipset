#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ipset.h"
#include "_cgo_export.h"

int writebuf( const char* format, ... ) {
  va_list args;
  va_start(args, format);
  outfn(va_arg(args, char *));
  va_end(args);
  return 0;
}

// Initializes a session with a write buffer for XML
struct ipset_session *session_init_xml() {
  struct ipset_session *session = ipset_session_init(writebuf);
  if (session) {
    ipset_session_output(session, IPSET_LIST_XML);
  }
  return session;
}


// Returns the ipset_arg with the given name
const struct ipset_arg*
get_ipset_arg(struct ipset_type *type, const char *argname){
  const struct ipset_arg *arg;
#ifdef IPSET_OPTARG_MAX
  int k;
  for (k = 0; type->cmd[IPSET_ADD].args[k] != IPSET_ARG_NONE; k++) {
    arg = ipset_keyword(type->cmd[IPSET_ADD].args[k]);
#else
  for (arg = type->args[IPSET_ADD]; arg->opt; arg++) {
#endif
    if (strcmp(argname, arg->name[0]) == 0){
      return arg;
    }
  }
  return NULL;
}
