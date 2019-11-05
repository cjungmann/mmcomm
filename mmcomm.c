#include <stdio.h>

#include <unistd.h>    // close()
#include <string.h>    // for memset()

#include <sys/types.h>

#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <netdb.h>       // For getaddrinfo() and supporting structures
#include <arpa/inet.h>   // Functions that convert addrinfo member values.
/* #include <netinet/in.h>  // conversion from addr (not working, not using) */

#include "addrinfo_debug.h"

/* Typedefs of callback function pointers: */
typedef void(*StrVal)(const char *val);
typedef void(*CBSocket)(int handle_socket);

void get_socket(const char *url, const char *service, CBSocket callback)
{
   struct addrinfo hints;
   struct addrinfo *result, *rp;

   int exit_value;
   int socket_handle;

   memset((void*)&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;    // Allow IP4 or IP6
   hints.ai_socktype = SOCK_DGRAM;
   hints.ai_socktype = 0;
   hints.ai_flags = AI_CANONNAME;
   hints.ai_protocol = 0;

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

         if (-1 != connect(socket_handle, rp->ai_addr, rp->ai_addrlen))
         {
            (*callback)(socket_handle);
            close(socket_handle);
            break;
         }
         else
            fprintf(stderr, "Connection attempt failed.\n");
      }

      freeaddrinfo(result);
   }
   else
   {
      fprintf(stderr, "getaddrinfo failed \"%s\".\n", gai_strerror(exit_value));
   }

}


void use_socket(int socket_handle)
{
   printf("Received a socket handle.  Yippee!\n");
}



void display_address(const char *str)
{
   printf("The string is \"%s\"\n", str);
}



int main(int argc, char **argv)
{
   get_socket("smtp.gmail.com", "587" , use_socket);
   /* get_socket("smtp.gmail.com", "587" , use_socket); */
   /* get_socket("www.cnn.com", "80" , use_socket); */

   return 0;
}
