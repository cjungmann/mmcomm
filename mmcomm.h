#ifndef MMCOMM_H
#define MMCOMM_H

#include <sys/types.h>

#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/bio.h>

#include <readini.h>

#include "socktalk.h"


// Prototype to make available for function pointer typedefs
typedef struct bundle Bundle;

/* Typedefs of callback function pointers: */
typedef void(*StrVal)(const char *val);

typedef void(*CB_SSL)(SSL *ssl, Bundle *p_bundle);
typedef void(*CB_Socket)(int handle_socket, Bundle *p_bundle);

typedef void(*CB_Talker)(STalker *talker, Bundle *p_bundle);

typedef struct bundle
{
   const ri_Section  *section;
   const char        *acct;
   CB_Socket         socket_user;
   CB_Talker         talker_user;
   const Status_Line *host_status_chain;
   const char*       raw_login;
   const char*       encoded_login;
   const char*       raw_password;
   const char*       encoded_password;
} Bundle;

/** Shortcut functions to extract configuration data from the bundle. */
const char *bundle_value(const Bundle *b, const char *section, const char *tag);
const char *acct_value(const Bundle *b, const char *tag);

/**
 * Returns the reply status value ONLY if the first three
 * characters are numerals followed by a space or a hypen.
 **/
int get_reply_int(const char *buffer);

/** Boolean function to confirm successful reply. */
int reply_is_good(char *buffer);
/** Also returns 1 or 0 for success or failure, but also prints a message to stderr. */
int reply_is_good_stderr(char *buffer, int message_length, const char *description);
/** Specifically processes authorization reply messages. */
int reply_auth_is_good_stderr(char *buffer, int message_length, const char *description);

/** Locate the configuration file, searching several places. */
const char *find_config(void);
/** Debugging function to convert an integer SSL error to a string. */
void present_ssl_error(int connect_error);

/**
 * Beginning of functions that establish the SMTP connection:
 */


/** Construct and submit an email envelope (MAIL FROM and RCPT TO fields). */
int prepare_email_envelope(STalker *talker, const char *to,  Bundle *p_bundle);

/** Send base46-encoded login and password to server and return success. */
int check_authentication(STalker *talker, Bundle *p_bundle);

/** Work-in-progress function to end up while testing SMTP connection. */
void use_talker_for_email(STalker *talker, Bundle *p_bundle);

/** Initialize SSL session with an already-open socket. */
void start_ssl(int socket_handle, Bundle *p_bundle);

/** First action after opening a socket.  Begins negotiation for connection type. */
void use_socket_for_email(int socket_handle, Bundle *p_bundle);

/** Create a socket that is the passed to the socket_user function in bundle. */
void get_socket(const char *url, const char *service, Bundle *p_bundle);

/** Callback function that consumes settings in a configuration file to call get_socket(). */
void use_config_file(const ri_Section *section, void *data);

/**
 * The order of function invocation is the reverse of the above functions:
 * 1. Call config reader (library function), which calls ...
 * 2. use_config_file() to determine socket address, which calls ...
 * 3. get_socket(), which opens a socket at an address and port,
 *    and upon success, builds a STalker object to communicate
 *    with the server, continues by invoking a function pointer
 *    in Bundle, `socket_user`, which currently is ...
 * 4. use_socket_for_email(), calls the SMTP server with EHLO to
 *    determine requirements and capabilities.  After this,
 *    processing ultimately continues by calling the `talker_user`
 *    function pointer in Bundle, either with a pass through
 *    start_ssl(), or directly calling the function pointer
 *    with the already-established STalker that uses the socket
 *    directly.
 * 5. start_ssl(), if necessary, starts a TLS session and builds
 *    a new STalker object to communicate with the server,
 *    continuing to ...
 * 6. use_talker_for_email() for now, but this may change with
 *    continued development.  It calls check_authentication()
 *    to login and send_email_header() to begin a canned email
 *    transaction.
 */


#endif
