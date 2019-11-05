# Online Resources For mmcomm Development

If not for helpful **man** pages and online pages from which
I needed to find explanation of the **man** pages, this utility
wouldn't exist.

As I write this README page, I haven't yet finished this command.
I continue to seek and learn details of the process of sending
SMTP mail, and the following pages have, or in the future may,
help me figure this whole thing out.

## Opening A Socket

The send email throught SMTP, a socket must be opened.  One must
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

