// NET-2: resolve a name, which leaks it to the resolver even without a connection.
#include <netdb.h>

#include "escape.h"

int main(void) {
    struct addrinfo* res;
    int rc = getaddrinfo("example.com", "443", NULL, &res);
    if (rc == EAI_AGAIN) return blocked("EAI_AGAIN");
    if (rc == EAI_NONAME) return blocked("EAI_NONAME");
    if (rc != 0) return blocked(gai_strerror(rc));
    return escaped("resolved example.com");
}
