#include <netdb.h>       // For getaddrinfo() and supporting structures
#include <arpa/inet.h>   // Functions that convert addrinfo member values.

const char *aistr_flags(int ai_flags);
const char *aistr_family(int ai_family);
const char *aistr_socktype(int ai_socktype);
const char *aistr_protocol(int ai_protocol);

void display_addrinfo(const struct addrinfo* ai);
