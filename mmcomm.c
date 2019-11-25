#include <stdio.h>

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

// Prototype to make available for function pointer typedefs
typedef struct bundle Bundle;

/* Typedefs of callback function pointers: */
typedef void(*StrVal)(const char *val);

typedef void(*CB_SSL)(SSL *ssl, Bundle *p_bundle);
typedef void(*CB_Socket)(int handle_socket, Bundle *p_bundle);

typedef struct bundle
{
   const ri_Section *section;
   const char       *acct;
   CB_SSL           ssl_user;
   CB_Socket        socket_user;
   const char       *encodedLogin;
   const char       *encodedPassword;
} Bundle;

const char *bundle_value(const Bundle *b, const char *section, const char *tag)
{
   return ri_find_section_value(b->section, section, tag);
}

const char *acct_value(const Bundle *b, const char *tag)
{
   return ri_find_section_value(b->section, b->acct, tag);
}

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
      display_addrinfo(result);

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

void use_socket(int socket_handle, Bundle *p_bundle)
{
   printf("Got a socket. Doin' nothin' with it.\n");
}


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
               // Successful Connection: call SSL user:
               (*p_bundle->ssl_user)(ssl, p_bundle);
            else if (connect_outcome == 0)
               // failed with controlled shutdown
               fprintf(stderr, "SSL connection failed and cleaned up.\n");
            else
            {
               fprintf(stderr, "[32;1mFailed to get an SSL connection (%d).[m\n", connect_outcome);
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
      fprintf(stderr, "The reply was good for %d characters.\n", message_length);
      return 1;
   }
   else
   {
      fprintf(stderr, "The server responded with %d characters.\n", message_length);
      buffer[message_length] = '\0';
      fprintf(stderr, "Error during **%s**: \"[44;1m%s[m\"", description, buffer);
      return 0;
   }
}

int greet_server(SSL *ssl, Bundle *p_bundle)
{
   const char *host = acct_value(p_bundle, "host");
   /* const char *user = acct_value(p_bundle, "user"); */
   /* const char *password = acct_value(p_bundle, "password"); */

   char buffer[2048];
   int message_length;
   int bytes_written, bytes_read;

   if (host)
   {
      message_length = sprintf(buffer, "HELO %s\r\n", host);
      bytes_written = SSL_write(ssl, buffer, message_length);
      if (bytes_written == message_length)
      {
         bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
         return reply_is_good_stderr(buffer, bytes_read, "server greeting");
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

void use_ssl(SSL *ssl, Bundle *p_bundle)
{
   char message[1024];
   int bytes_to_write, bytes_read;

   const char *from, *to, *subject;

   const char *format = "From: %s\r\n"
      "To: %s\r\n"
      "Subject: %s\r\n"
      "\r\n"
      "This is a new email message.\r\n"
      "It has a few lines of test,\r\n"
      "but it will be merged into a\r\n"
      "single block of stack memory\r\n"
      "for submission to an SMTP\r\n"
      "server.\r\n"
      ".\r\n";

   printf("Got a SSL handle.\n");

   if (greet_server(ssl, p_bundle))
   {
      to = "chuck@cpjj.net";

      if (request_email_permission(ssl, to, p_bundle))
      {
         // Composing email
         from = acct_value(p_bundle, "from");
         subject = "Test email from mmcomm, a C-language mailer";

         bytes_to_write = sprintf(message, format, from, to, subject);
         SSL_write(ssl, message, bytes_to_write);
         bytes_read = SSL_read(ssl, message, sizeof(message));

         message[bytes_read] = '\0';
         printf("%s\n", message);
      }
   }
}


void display_address(const char *str)
{
   printf("The string is \"%s\"\n", str);
}


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

void use_config_file(const ri_Section *section)
{
   const char *acct, *host, *port_str;

   Bundle bundle;
   memset(&bundle, 0, sizeof(Bundle));

   acct = ri_find_section_value(section, "defaults", "default-account");
   if (acct)
   {
      bundle.section = section;
      bundle.ssl_user = use_ssl;
      bundle.socket_user = start_ssl;
      bundle.acct = acct;

      host = acct_value(&bundle, "host");
      port_str = acct_value(&bundle, "port");

      const char *login = acct_value(&bundle, "user");
      const char *password = acct_value(&bundle, "password");
      if (login && password)
      {
         int raw_len_login = strlen(login);
         int raw_len_password = strlen(password);
         int len_login = c64_encode_required_buffer_length(raw_len_login);
         int len_password = c64_encode_required_buffer_length(raw_len_password);

         char *buffer = (char*)alloca(len_login);
         c64_encode_to_buffer(login, raw_len_login, (uint32_t*)buffer, len_login);
         bundle.encodedLogin = buffer;

         buffer = (char*)alloca(len_password);
         c64_encode_to_buffer(password, raw_len_password, (uint32_t*)buffer, len_password);
         bundle.encodedPassword = buffer;
      }

      get_socket(host, port_str, &bundle);
   }
}

/**
 * @brief Keeping socket-only calls around for testing.
 */
void simple_socket_test()
{
   Bundle bundle;
   memset(&bundle, 0, sizeof(Bundle));
   bundle.socket_user = use_socket;

   get_socket("smtp.gmail.com", "587" , &bundle );
   get_socket("smtp.gmail.com", "587" , &bundle);
   get_socket("www.cnn.com", "80" , &bundle);
}


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
