#include <libipset/data.h>
#include <libipset/parse.h>
#include <libipset/session.h>
#include <libipset/types.h>

// Initializes a session with a write buffer for XML
struct ipset_session *session_init_xml();

// Returns the ipset_arg with the given name
const struct ipset_arg*
get_ipset_arg(struct ipset_type *type, const char *argname);