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
#include "mmcomm.h"

// Global flag to report emailing steps
unsigned int verbose = 0;

const char *bundle_value(const Bundle *b, const char *section, const char *tag)
{
   return ri_find_section_value(b->section, section, tag);
}

const char *acct_value(const Bundle *b, const char *tag)
{
   return ri_find_section_value(b->section, b->acct, tag);
}

int get_reply_int(const char *buffer)
{
   int value = -1;
   if (isdigit(buffer[0])
       && isdigit(buffer[1])
       && isdigit(buffer[2])
       && ( buffer[3] == '-' || isspace(buffer[3])) )
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
      if (verbose)
         printf("status: %.*s\n", message_length, buffer);
      return 1;
   }
   else
   {
      fprintf(stderr, "Error during **%s**: \"[44;1m%.*s[m\"",
              description,
              message_length,
              buffer);
      return 0;
   }
}

int reply_auth_is_good_stderr(char *buffer, int message_length, const char *description)
{
   int advance_chars;

   int status;
   const char *line;
   int line_len;

   int success = 0;

   const char *ptr = buffer;
   while (*ptr)
   {
      advance_chars = walk_status_reply(ptr, &status, &line, &line_len);
      switch(advance_chars)
      {
         case -1:
            fprintf(stderr, "Error processing replys \"%s\".\n", buffer);
         case 0:
            ptr = "";
            break;
         default:
            if (status == 334)
            {
               // decode message, call new socktalk function?
               success = 1;
            }
            else
               printf("Auth response: (%d) [44;1m%.*s[m.\n", status, line_len, line);

            ptr += advance_chars;
            break;
      }
   }

   return success;
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

int prepare_email_envelope(STalker *talker, const char *to,  const char *from)
{
   char buffer[1024];

   int smtp_reply;
   int bytes_sent = 0, bytes_read = 0;

   bytes_sent += stk_send_line(talker, "MAIL FROM: <", from, ">", NULL);
   bytes_read = stk_recv_line(talker, buffer, sizeof(buffer));

   if (reply_is_good_stderr(buffer, bytes_read, "mail_from"))
   {
      bytes_sent += stk_send_line(talker, "RCPT TO: <", to, ">", NULL);
      bytes_read = stk_recv_line(talker, buffer, sizeof(buffer));

      if (reply_is_good_stderr(buffer, bytes_read, "rcpt_to"))
      {
         bytes_sent += stk_send_line(talker, "DATA", NULL);
         bytes_read = stk_recv_line(talker, buffer, sizeof(buffer));

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

int check_authentication(STalker *talker, Bundle *p_bundle)
{
   const char *login_str = p_bundle->encoded_login;
   const char *pword_str = p_bundle->encoded_password;
   size_t bytes_read = 0;

   char buffer[1000];
   stk_send_line(talker, "AUTH LOGIN", NULL);
   bytes_read = stk_recv_line(talker, buffer, sizeof(buffer));

   if (verbose)
      fprintf(stderr, "status: AUTH LOGIN response: %.*s\n", (int)bytes_read, buffer);

   if (reply_auth_is_good_stderr(buffer, bytes_read, "Request AUTH LOGIN"))
   {
      if (verbose)
         fprintf(stderr, "status: Sending encoded username: '%s'\n", login_str);

      stk_send_line(talker, login_str, NULL);
      bytes_read = stk_recv_line(talker, buffer, sizeof(buffer));
      if (reply_auth_is_good_stderr(buffer, bytes_read, "Authorization, sent login"))
      {
         if (verbose)
            fprintf(stderr, "status: Sending encoded password: '%s'\n", pword_str);

         stk_send_line(talker, pword_str, NULL);
         bytes_read = stk_recv_line(talker, buffer, sizeof(buffer));
         if (reply_is_good_stderr(buffer, bytes_read, "Authorization, sent password"))
            return 1;
         else
            fprintf(stderr, "authorization failed.\n");
      }
   }

   return 0;
}

/**
 * @brief Temporary, debugging callback to confirm that start_ssl() has worked.
 */
void use_talker_for_email(STalker *talker, Bundle *p_bundle)
{
   char buffer[1000];
   size_t bytes_read = 0;

   const char *send_from;
   const char *default_from = acct_value(p_bundle, "from");
   int mail_count = 0;

   MC_Mail email_item;
   Email_Tap email_tap = p_bundle->email_tap;

   if (!email_tap)
   {
      fprintf(stderr, "Emailing failed due to missing email tap.\n");
      return;
   }

   if (verbose)
      fprintf(stderr, "status: about to check authentication.\n");

   if (check_authentication(talker, p_bundle));
   {
      while ( (*email_tap)(&email_item, p_bundle->email_data) )
      {
         // Use best available *from* address
         send_from = email_item.From ? email_item.From : default_from;

         if (verbose)
            fprintf(stderr,  "status: Sending email to %s...", email_item.To);

         if (prepare_email_envelope(talker, email_item.To, send_from))
         {
            stk_send_line(talker, "To: ", email_item.To, NULL);
            stk_send_line(talker, "From: " , send_from, NULL);
            if (email_item.Reply_To)
               stk_send_line(talker, "Reply-To: " , email_item.Reply_To, NULL);
            if (email_item.CC)
               stk_send_line(talker, "CC: " , email_item.CC, NULL);
            if (email_item.BCC)
               stk_send_line(talker, "BCC: " , email_item.BCC, NULL);
            if (email_item.Subject)
               stk_send_line(talker, "Subject: " , email_item.Subject, NULL);

            // Blank line to indicate email headers are complete
            stk_send_line(talker, NULL);

            if (email_item.message)
               stk_send_line(talker, email_item.message, NULL);

            // Indicate end-of email transmission;
            stk_send_line(talker, ".", NULL);

            bytes_read += stk_recv_line(talker, buffer, sizeof(buffer));
            if (reply_is_good(buffer))
            {
               ++mail_count;

               if (verbose)
                  fprintf(stderr, "status: email sent.\n");
            }
            else if (verbose)
               fprintf(stderr, "status: failed to send email.\n");
         }
         else if (verbose)
            fprintf(stderr, "status: envelope failed.\n");
      }

      stk_send_line(talker, "QUIT", NULL);
      bytes_read += stk_recv_line(talker, buffer, sizeof(buffer));
   }

   if (verbose)
      fprintf(stderr, "status: %d emails sent, total response bytes read: %lu.\n", mail_count, bytes_read);
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
            {
               STalker talker;
               init_ssl_talker(&talker, ssl);

               if (verbose)
                  fprintf(stderr, "status: SSL protocol initialized.\n");

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
            fprintf(stderr, "Failed to get an SSL object.\n");
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

      if (verbose)
         fprintf(stderr, "status: Response to EHLO\n%.*s\n", (int)bytes_read, buffer);

      bptr = buffer;
      while (*bptr)
      {
         chars_to_advance = walk_status_reply(bptr, &status_code, &cur_line, &line_len);
         if (chars_to_advance == 0)
            break;
         else if (chars_to_advance == -1)
         {
            fprintf(stderr, "Error walking status reply [44;1m%s[m.\n", buffer);
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

      if (verbose)
         show_status_chain(sl_anchor);

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
         if (verbose)
            fprintf(stderr, "status: Not using TLS, start with socket.\n");

         init_sock_talker(&talker, socket_handle);
         (*p_bundle->talker_user)(&talker, p_bundle);
      }
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
      if (verbose)
         display_addrinfo(result);

      for (rp = result; rp; rp = rp->ai_next)
      {
         exit_value = 1;

         if ((rp->ai_family == PF_INET || rp->ai_family == PF_INET6)
             && rp->ai_socktype == SOCK_STREAM
             && rp->ai_protocol == IPPROTO_TCP)
         {
            socket_handle = socket(rp->ai_family,
                                   rp->ai_socktype,
                                   rp->ai_protocol);

            if (socket_handle == -1)
               continue;

            if (0 == connect(socket_handle, rp->ai_addr, rp->ai_addrlen))
            {
               if (verbose)
                  fprintf(stderr, "status: Socket successfully opened.\n");

               exit_value = 0;
               (*p_bundle->socket_user)(socket_handle, p_bundle);

               close(socket_handle);
               break;
            }

         }
      }

      if (exit_value)
         fprintf(stderr, "Socket connection failed for URL='%s' (%s).\n", url, strerror(errno));

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
void use_config_file(const ri_Section *section, void* data)
{
   const char *acct, *host, *port_str;
   const char *login = NULL, *password = NULL;

   Bundle *p_bundle = (Bundle*)data;

   if (verbose)
      fprintf(stderr, "status: Successfully opened the config file.\n");

   // Prefer preset account name to config file values:
   if (p_bundle->acct)
      acct= p_bundle->acct;
   else
      acct = p_bundle->acct = ri_find_section_value(section, "defaults", "default-account");

   if (acct)
   {
      if (verbose)
         fprintf(stderr, "status: Using account '%s'.\n", acct);

      p_bundle->section = section;
      /* bundle.socket_user = start_ssl; */
      p_bundle->socket_user = use_socket_for_email;
      p_bundle->talker_user = use_talker_for_email;
      p_bundle->acct = acct;

      host = acct_value(p_bundle, "host");
      port_str = acct_value(p_bundle, "port");

      // Prefer preset login and password values to config file values:
      if (p_bundle->raw_login)
         login = p_bundle->raw_login;
      else
         login = acct_value(p_bundle,"from");

      if (p_bundle->raw_password)
         password = p_bundle->raw_password;
      else
         password = acct_value(p_bundle,"password");

      if (login && password)
      {
         /* c64_set_special_chars("+/"); */

         int raw_len_login = strlen(login);
         int raw_len_password = strlen(password);
         int len_login = c64_encode_required_buffer_length(raw_len_login);
         int len_password = c64_encode_required_buffer_length(raw_len_password);

         char *buffer = (char*)alloca(len_login);
         c64_encode_to_buffer(login, raw_len_login, (uint32_t*)buffer, len_login);
         p_bundle->encoded_login = buffer;

         buffer = (char*)alloca(len_password);
         c64_encode_to_buffer(password, raw_len_password, (uint32_t*)buffer, len_password);
         p_bundle->encoded_password = buffer;


         /* p_bundle->encoded_login = login; */
         /* p_bundle->encoded_password = password; */

      }

      get_socket(host, port_str, p_bundle);
   }
}

typedef struct _test_email_atom
{
   const char *to;
   const char *subject;
   const char *msg;
} EAtom;

typedef struct _email_data
{
   const EAtom *earray;
   const EAtom *cur;
   const EAtom *end;
} EData;

EAtom edata_emails[] = {
   {"chuck@cpjj.net",          "First Test Email", "This is an email test, the first." },
   {"chuckj60@gmail.com",      "First Test Email", "This is an email test, the first." },
   {"chuckjungmann@gmail.com", "First Test Email", "This is an email test, the first." }
};


void reset_EData(EData *ed)        { ed->cur = ed->earray; }
int inrange_EData(const EData *ed) { return ed->cur < ed->end; }
void increment_EData(EData *ed)    { ++(ed->cur); }

void construct_EData(EData *ed, const EAtom *eatoms, size_t count)
{
   ed->earray = eatoms;
   ed->end = &eatoms[count];
   reset_EData(ed);
};


int Test_Email_Tap(MC_Mail *mail, void *data)
{
   EData *edata = (EData*)data;
   const EAtom *eatom;

   memset(mail, 0, sizeof(MC_Mail));

   if (inrange_EData(edata))
   {
      eatom = edata->cur;

      mail->To = eatom->to;
      mail->Subject = eatom->subject;
      mail->message = eatom->msg;

      increment_EData(edata);

      return 1;
   }
   else
      return 0;
}



void show_usage(void)
{
   const char *options[] = {
      "-a profile account",
      "-l login name (corresponds to 'user' config value)",
      "-m MAIL FROM",
      "-p port",
      "-r RCPT TO",
      "-s subject"
      "-u URL",
      "-w password",
      NULL
   };

   const char **ptr = options;
   while (*ptr)
   {
      printf("%s\n", *ptr);
      ++ptr;
   }

   printf("and that's it.\n");
}
   

int main(int argc, const char **argv)
{
   const char **parg = argv;
   const char **end = parg + argc;
   const char *str;

   Bundle bundle;
   memset(&bundle, 0, sizeof(Bundle));

   bundle.email_tap = Test_Email_Tap;

   EData edata;
   int edata_len = sizeof(edata_emails) / sizeof(EAtom);
   construct_EData(&edata, edata_emails, edata_len);

   bundle.email_data = (void*)&edata;

   while (++parg < end)
   {
      str = *parg;
      if (*str == '-')
      {
         while (*++str)
         {
            switch(*str)
            {
               case 'a':
                  bundle.acct = *++parg;
                  goto abandon_arg;
               case 'h':
                  show_usage();
                  goto abandon_app;
               case 'l':
                  bundle.raw_login = *++parg;
                  goto abandon_arg;
               case 'm':  // MAIL FROM
                  break;
               case 'p': // port
                  break;
               case 'r': // RCPT TO
                  break;
               case 's': // subject
                  break;
               case 'u': // URL
                  break;
               case 'v': // verbose
                  verbose = 1;
                  break;
               case 'w': // password
                  bundle.raw_password = *++parg;
                  goto abandon_arg;
               default:
                  break;
            };
         }

         // "unstructured" break: tiny performance improvement, but
         // the alternative bugs me: to set a flag to break the _while_
         // loop requires an additional variable (no big deal), but
         // also an otherwise unnecessary condition check for each
         // iteration.
         abandon_arg:
         ; // minimum required code following the label
      }

   }

   const char *fpath = find_config();
   if (fpath)
   {
      if (verbose)
         fprintf(stderr, "status: Using configuration file at '%s'\n", fpath);

      ri_read_file(fpath, use_config_file, (void*)&bundle);
   }
   else
      fprintf(stderr, "Failed to find a mmcomm configuration file.\n");

  abandon_app:
   ;

   return 0;
}
