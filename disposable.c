


/**
 * @brief Saved/previous function that converses with SMTP server in attempt to send email.
 */
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

      /* if (request_email_permission(ssl, to, p_bundle)) */
      /* { */
      /*    // Composing email */
      /*    from = acct_value(p_bundle, "from"); */
      /*    subject = "Test email from mmcomm, a C-language mailer"; */

      /*    bytes_to_write = sprintf(message, format, from, to, subject); */
      /*    SSL_write(ssl, message, bytes_to_write); */
      /*    bytes_read = SSL_read(ssl, message, sizeof(message)); */

      /*    if (p_bundle->encoded_login) */
      /*    { */
      /*    } */

      /*    message[bytes_read] = '\0'; */
      /*    printf("%s\n", message); */
      /* } */
   }
}

void use_socket(int socket_handle, Bundle *p_bundle)
{
   printf("Got a socket. Doin' nothin' with it.\n");
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


