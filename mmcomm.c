#include <stdio.h>
#include <stdlib.h>    // atoi()

#include <unistd.h>    // close()
#include <string.h>    // for memset()
#include <stdarg.h>    // for va_arg, etc.

#include <ctype.h>     // for isdigit

#include <sys/types.h>

#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/bio.h>

#include <code64.h>      // for encoding username and password

#include <netdb.h>       // For getaddrinfo() and supporting structures
#include <arpa/inet.h>   // Functions that convert addrinfo member values.
/* #include <netinet/in.h>  // conversion from addr (not working, not using) */

#include "addrinfo_debug.h"

#include <readini.h>    // For reading the configuration file
#include <code64.h>     // base64 encoding for username and password

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

const char *find_config(void)
{
   static const char* paths[] = { "~/.mmcomm.conf", "/etc/mmcomm.conf", "./mmcomm.conf", NULL };
   const char** dname = paths;

   while (*dname)
   {
      if (0 == access(*dname, F_OK|R_OK))
         return *dname;
      dname++;
   }

   return NULL;
}

const char *bundle_value(const Bundle *b, const char *section, const char *tag)
{
   return ri_find_section_value(b->section, section, tag);
}

const char *acct_value(const Bundle *b, const char *tag)
{
   return ri_find_section_value(b->section, b->acct, tag);
}

void present_ssl_error(int connect_error)
{
   const char *msg = NULL;
   switch(connect_error)
   {
      case SSL_ERROR_NONE:
         msg = "SSL_ERROR_NONE";
         break;
      case SSL_ERROR_ZERO_RETURN:
         msg = "SSL_ERROR_ZERO_RETURN";
         break;
      case SSL_ERROR_WANT_READ:
         msg = "SSL_ERROR_WANT_READ";
         break;
      case SSL_ERROR_WANT_WRITE:
         msg = "SSL_ERROR_WANT_WRITE";
         break;
      case SSL_ERROR_WANT_CONNECT:
         msg = "SSL_ERROR_WANT_CONNECT";
         break;
      case SSL_ERROR_WANT_ACCEPT:
         msg = "SSL_ERROR_WANT_ACCEPT";
         break;
      case SSL_ERROR_WANT_X509_LOOKUP:
         msg = "SSL_ERROR_X509_LOOKUP";
         break;
      case SSL_ERROR_SYSCALL:
         msg = "SSL_ERROR_SYSCALL";
         break;
      case SSL_ERROR_SSL:
         msg = "SSL_ERROR_SSL";
         break;
      default:
         msg = "unrecognized ssl error_";
         break;
   }

   if (msg)
      fprintf(stderr, "Failed to make SSL connection (%s).\n", msg);
}

void print_message(SSL *ssl, ...)
{
   int line_count, char_count;
   int found_end_of_headers = 0;
   va_list ap;
   va_start(ap, ssl);
   const char *line;

   line_count = 0;
   char_count = 0;

   line = va_arg(ap, const char*);
   while(line)
   {
      // Count all lines, even blank line between header and body:
      ++line_count;
      
      // Do not count the first "--", which
      // indicates the end of header information.
      if (!found_end_of_headers && 0==strcmp(line, "--"))
         found_end_of_headers = 1;
      else
         char_count += strlen(line);

      line = va_arg(ap, const char*);
   }

   va_end(ap);

   // Allowance for /r/n at end of each line:
   char_count += (line_count * 2);

   printf("The message would have had %d lines and a total of %d characters.\n",
          line_count,
          char_count);
}

int get_reply_int(const char *buffer)
{
   int value = -1;
   if (isdigit(buffer[0]) && isdigit(buffer[1]) && isdigit(buffer[2]) && isspace(buffer[3]))
   {
      value = 100 * (buffer[0] - '0');
      value += 10 * (buffer[1] - '0');
      value += (buffer[2] - '0');
   }

   return value;
}

int reply_is_good(char *buffer)
{
   int value = get_reply_int(buffer);
   return (value >= 200 && value < 300);
}

int reply_is_good_stderr(char *buffer, int message_length, const char *description)
{
   if (reply_is_good(buffer))
   {
      fprintf(stderr, "(%s) The reply was good for %d characters.\n", description, message_length);
      printf("%.*s\n", message_length, buffer);
      return 1;
   }
   else
   {
      fprintf(stderr, "(%s) The server responded with %d characters.\n", description, message_length);
      buffer[message_length] = '\0';
      fprintf(stderr, "Error during **%s**: \"[44;1m%s[m\"", description, buffer);
      return 0;
   }
}

void send_message(SSL *ssl, const char *message, char *response, int response_length)
{
   fprintf(stderr, "sending [33;1m%s[m.  ", message);
   int b_sent = SSL_write(ssl, message, strlen(message));
   b_sent += SSL_write(ssl, "\r\n", 2);
   fprintf(stderr, " sent %d bytes.\n", b_sent);

   SSL_read(ssl, response, response_length);
}

int send_authentication(SSL *ssl, Bundle *p_bundle)
{
   const char *login_str = p_bundle->encoded_login;
   const char *pword_str = p_bundle->encoded_password;

   /* const char *login_str = p_bundle->raw_login; */
   /* const char *pword_str = p_bundle->raw_password; */

   char buffer[1000];
   send_message(ssl, "AUTH LOGIN", buffer, sizeof(buffer));
   printf("After auth_login:  [33;1m%s[m\n", buffer);
   send_message(ssl, login_str, buffer, sizeof(buffer));
   printf("After login sent:  [33;1m%s[m\n", buffer);
   send_message(ssl, pword_str, buffer, sizeof(buffer));
   printf("After password sent:  [33;1m%s[m\n", buffer);

   return 1;
}

int greet_server(SSL *ssl, Bundle *p_bundle)
{
   const char *host = acct_value(p_bundle, "host");

   char buffer[2048];
   int message_length;
   int bytes_written = 0, bytes_read = 0;

   if (host)
   {
      /* message_length = sprintf(buffer, "HELO %s\r\n", host); */
      message_length = sprintf(buffer, "EHLO %s\r\n", host);
      bytes_written += SSL_write(ssl, buffer, message_length);
      if (bytes_written == message_length)
      {
         bytes_read += SSL_read(ssl, buffer, sizeof(buffer));
         fprintf(stderr, "After HELO, [45;1m%s[m.\n", buffer);

         if (p_bundle->encoded_login)
            return send_authentication(ssl, p_bundle);
         else if (reply_is_good(buffer))
            return 1;
         /* return reply_is_good_stderr(buffer, bytes_read, "server greeting"); */
      }
   }

   return 0;
}

int request_email_permission(SSL *ssl, const char *to,  Bundle *p_bundle)
{
   char buffer[1024];

   int smtp_reply;
   int bytes_sent = 0, bytes_read = 0, bytes_to_send;
   const char *from = acct_value(p_bundle, "from");

   bytes_to_send = sprintf(buffer, "MAIL FROM:<%s>\r\n", from);
   bytes_sent += SSL_write(ssl, buffer, bytes_to_send);

   bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
   if (reply_is_good_stderr(buffer, bytes_read, "mail_from"))
   {
      bytes_to_send = sprintf(buffer, "RCPT TO:<%s>\r\n", to);
      bytes_sent += SSL_write(ssl, buffer, bytes_to_send);

      bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
      if (reply_is_good_stderr(buffer, bytes_read, "rcpt_to"))
      {
         bytes_sent += SSL_write(ssl, "DATA\r\n", 6);
         bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
         smtp_reply = get_reply_int(buffer);
         if (smtp_reply == 354)
            return 1;
         else
         {
            buffer[bytes_read] = '\0';
            fprintf(stderr, "Expected code 354, got %d instead. \"%s\"\n", smtp_reply, buffer);
         }
      }
   }

   return 0;
}

/**
 * @brief Temporary, debugging callback to confirm that start_ssl() has worked.
 */
void use_talker_for_email(STalker *talker, Bundle *p_bundle)
{
   printf("Got to the talker routine.  Everything should be prepared\n"
          "to commence a conversation with the SMTP server.\n");
}

/**
 * @brief Initialize SSL session with a socket if the SMTP server requests it.
 */
void start_ssl(int socket_handle, Bundle *p_bundle)
{
   const SSL_METHOD *method;
   SSL_CTX *context;
   SSL *ssl;
   int connect_outcome;

   OpenSSL_add_all_algorithms();
   /* ERR_load_BIO_strings(); */
   ERR_load_crypto_strings();
   SSL_load_error_strings();

   /* OPENSSL_config(NULL); */

   SSL_library_init();

   method = SSLv23_client_method();
   if (method)
   {
      context = SSL_CTX_new(method);

      if (context)
      {
         // Following two not included in most recent example code I found.
         // It may be appropriate to uncomment these lines as I learn more.
         /* SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL); */
         /* SSL_CTX_set_verify_depth(context, 4); */

         // We could set some flags, but I'm not doing it until I need to and I understand 'em
         /* const long CTX_flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION; */
         /* SSL_CTX_set_options(context, CTX_flags); */
         SSL_CTX_set_options(context, SSL_OP_NO_SSLv2);

         ssl = SSL_new(context);
         if (ssl)
         {
            SSL_set_fd(ssl, socket_handle);

            connect_outcome = SSL_connect(ssl);

            if (connect_outcome == 1)
            {
               STalker talker;
               init_ssl_talker(&talker, ssl);
               (*p_bundle->talker_user)(&talker, p_bundle);
            }
            else if (connect_outcome == 0)
               // failed with controlled shutdown
               fprintf(stderr, "SSL connection failed and cleaned up.\n");
            else
            {
               present_ssl_error(SSL_get_error(ssl, connect_outcome));
               ERR_print_errors_fp(stderr);
            }

            SSL_free(ssl);
         }
         else  // failed to get an SSL
         {
            fprintf(stderr, "[32;1mFailed to get an SSL object.[m\n");
            ERR_print_errors_fp(stderr);
         }

         SSL_CTX_free(context);
      }
      else // failed to get a context
      {
         fprintf(stderr, "[32;1mFailed to get an SSL context.[m\n");
         ERR_print_errors_fp(stderr);
      }
   }
   else
      fprintf(stderr, "Failed to get SSL method.\n");
}

/**
 * @brief Initialize conversation with SMTP server, get EHLO (extended HELO) capabilities
 *        in preparation to commence email transactions.
 */

void use_socket_for_email(int socket_handle, Bundle *p_bundle)
{
   size_t bytes_read = 0;
   size_t bytes_written = 0;
   size_t total_read = 0;
   char buffer[1024];

   // Variables for parsing status reply string
   const char *bptr;
   int chars_to_advance;
   int status_code;
   const char *cur_line;
   int line_len;
   STalker *stalker = (STalker *)alloca(sizeof(STalker));
   init_sock_talker(stalker, socket_handle);

   // Anchor to status reply chain:
   struct _status_line *sl_anchor = NULL, *sl_tail = NULL;
   struct _status_line *status_line = NULL;
   char *temp_message;

   const char *host = acct_value(p_bundle, "host");

   total_read += bytes_read = stk_recv_line(stalker, buffer, sizeof(buffer));

   status_code = atoi(buffer);
   if (status_code >=200 && status_code < 300)
   {
      bytes_written += stk_send_line(stalker, "EHLO ", host, NULL);
      total_read += bytes_read = stk_recv_line(stalker, buffer, sizeof(buffer));

      bptr = buffer;
      while (*bptr)
      {
         chars_to_advance = walk_status_reply(bptr, &status_code, &cur_line, &line_len);
         if (chars_to_advance == 0)
            break;
         else if (chars_to_advance == -1)
         {
            printf("Error walking status reply [44;1m%s[m.\n", buffer);
            break;
         }
         else
         {
            status_line = (Status_Line*)alloca(sizeof(Status_Line));
            memset(status_line, 0, sizeof(Status_Line));

            // Allocate, and copy to new memory, the current message line:
            temp_message = (char*)alloca(1 + line_len);
            memcpy(temp_message, cur_line, line_len);
            temp_message[line_len] = '\0';

            status_line->status = status_code;
            status_line->message = temp_message;

            if (sl_tail)
            {
               sl_tail->next = status_line;
               sl_tail = status_line;
            }
            else
               sl_tail = sl_anchor = status_line;

            bptr += chars_to_advance;
         }
      }

      p_bundle->host_status_chain = sl_anchor;

      if (seek_status_message(sl_anchor, "STARTTLS"))
      {
         // If STARTTLS is available, we must send a request
         // to begin TLS mode.
         bytes_written += stk_send_line(stalker, "STARTTLS", NULL);
         total_read += bytes_read = stk_recv_line(stalker, buffer, sizeof(buffer));

         // Only continue if the TLS request was granted:
         status_code = atoi(buffer);
         if (status_code >= 200 && status_code < 300)
            start_ssl(socket_handle, p_bundle);
         else
            fprintf(stderr, "STARTTLS request denied (%s).\n", buffer);
      }
      else
      {
         STalker talker;
         init_sock_talker(&talker, socket_handle);
         (*p_bundle->talker_user)(&talker, p_bundle);
      }

      /* show_status_chain(sl_anchor); */
   }
}

/**
 * @brief Open a socket at a URL and service, pass newly open socket to next step.
 */
void get_socket(const char *url, const char *service, Bundle *p_bundle)
{
   struct addrinfo hints;
   struct addrinfo *result, *rp;

   int exit_value;
   int socket_handle;

   memset((void*)&hints, 0, sizeof(struct addrinfo));
   /* hints.ai_family = AF_UNSPEC;    // Allow IP4 or IP6 */
   hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_socktype = 0;
   hints.ai_flags = AI_CANONNAME;
   hints.ai_protocol = IPPROTO_IP;

   exit_value = getaddrinfo(url, service, &hints, &result);

   if (exit_value==0)
   {
      // The next statement shows debugging info about the addrinfo object:
      /* display_addrinfo(result); */

      for (rp = result; rp; rp = rp->ai_next)
      {
         socket_handle = socket(rp->ai_family,
                         rp->ai_socktype,
                         rp->ai_protocol);

         if (socket_handle == -1)
            continue;

         if (0 == connect(socket_handle, rp->ai_addr, rp->ai_addrlen))
         {
            (*p_bundle->socket_user)(socket_handle, p_bundle);
            close(socket_handle);
            break;
         }
         else
            fprintf(stderr, "Connection attempt failed (%s).\n", strerror(errno));
      }

      freeaddrinfo(result);
   }
   else
   {
      fprintf(stderr, "getaddrinfo failed \"%s\".\n", gai_strerror(exit_value));
   }
}

/**
 * @brief Use values from config file to begin the SMTP connection.
 */
void use_config_file(const ri_Section *section)
{
   const char *acct, *host, *port_str;

   Bundle bundle;
   memset(&bundle, 0, sizeof(Bundle));

   acct = ri_find_section_value(section, "defaults", "default-account");
   if (acct)
   {
      bundle.section = section;
      /* bundle.socket_user = start_ssl; */
      bundle.socket_user = use_socket_for_email;
      bundle.talker_user = use_talker_for_email;
      bundle.acct = acct;

      host = acct_value(&bundle, "host");
      port_str = acct_value(&bundle, "port");

      const char *login = acct_value(&bundle, "user");
      const char *password = acct_value(&bundle, "password");
      if (login && password)
      {
         bundle.raw_login = login;
         bundle.raw_password = password;

         c64_set_special_chars("+/");

         int raw_len_login = strlen(login);
         int raw_len_password = strlen(password);
         int len_login = c64_encode_required_buffer_length(raw_len_login);
         int len_password = c64_encode_required_buffer_length(raw_len_password);

         char *buffer = (char*)alloca(len_login);
         c64_encode_to_buffer(login, raw_len_login, (uint32_t*)buffer, len_login);
         bundle.encoded_login = buffer;

         buffer = (char*)alloca(len_password);
         c64_encode_to_buffer(password, raw_len_password, (uint32_t*)buffer, len_password);
         bundle.encoded_password = buffer;
      }

      get_socket(host, port_str, &bundle);
   }
}


#include "disposable.c"

int main(int argc, char **argv)
{
   /* simple_socket_test(); */

   const char *fpath = find_config();
   if (fpath)
      ri_read_file(fpath, use_config_file);
   else
      fprintf(stderr, "Failed to find a mmcomm configuration file.\n");


   return 0;
}
