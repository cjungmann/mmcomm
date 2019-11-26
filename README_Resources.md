# Online Resources For mmcomm Development

If not for helpful **man** pages and online pages from which
I needed to find explanation of the **man** pages, this utility
wouldn't exist.

As I write this README page, I haven't yet finished this command.
I continue to seek and learn details of the process of sending
SMTP mail, and the following pages have, or in the future may,
help me figure this whole thing out.

## SMTP Documnetation

- [SMTP Standard Document](https://tools.ietf.org/html/rfc5321)  
  There is a lot here.  Links to specific sections are found below.

## Opening A Socket

The send email through SMTP, a socket must be opened.  One must
find the IP address of a domain before the socket can be opened.

- Getting the mail server's IP address through **getaddrinfo()**,
  a C function that uses various local and online resources to
  reconcile a domain.
  This [helpful **getaddrinfo** page](https://jameshfisher.com/2018/02/03/what-does-getaddrinfo-do/)
  helped me understand how to use **getaddrinfo**.

- [SMTP with telnet](https://www.wikihow.com/Send-Email-Using-Telnet)
  Understanding the sequence of communications with the SMTP
  server will inform that development of an automated process.

  The steps on this page only work for unsecure email.  That is,
  an SMTP conversation without using TLS.

- [SMTP with TLS](https://halon.io/blog/how-to-test-smtp-servers-using-the-command-line/)

- [Code Project SMTP Client with SSL/TSL](https://www.codeproject.com/Articles/98355/SMTP-Client-with-SSL-TLS)

- [Open SSL Client in C](https://aticleworld.com/ssl-server-client-using-openssl-in-c/)

- [Perhaps more useful; email/gmail specific](https://codevlog.com/gmailsmtp-gmail-com-using-c-programming-ssl/118)


## Interpreting Replys

- [SMTP Reply Codes](https://serversmtp.com/smtp-error/) explains codes likes 354, 250, etc.
- [Wiki on SMTP Reply Codes](https://en.wikipedia.org/wiki/List_of_SMTP_server_return_codes)
- [SMTP Standards about replies](https://tools.ietf.org/html/rfc5321#section-4.1.1.1














)
