# Project Mail Merge COMMand (mmcomm)

I could not find a command line program that would send
multiple emails with one call, so I am making this one to
serve that purpose.

I have been using **msmtp** to send emails, but each call
to that command requires establishing a new SMTP socket,
taking almost a second per email.

The goal of this program is to open an SMTP session once
and use it to send a bunch of emails.  I'm not sure how I'll
do it yet, but one possibility is to have it repeatedly call
an external command that submits individual emails to the
established socket.  We'll see.

## Resources

As I investigate the SMTP process, I will save links to 
resources that help me understand it.  These links are
compiled on the [Resources Page](README_Resources.md).

