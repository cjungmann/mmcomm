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
int reply_is_good_stderr(char *buffer, int message_length, const char *description)



/** Locate the configuration file, searching several places. */
const char *find_config(void);
/** Debugging function to convert an integer SSL error to a string. */
void present_ssl_error(int connect_error);

#endif
