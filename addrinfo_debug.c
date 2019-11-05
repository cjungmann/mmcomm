#include <stdio.h>
#include <string.h>     // for strlen(), strcpy(), etc

#include <netdb.h>      // For getaddrinfo() and supporting structures
#include <arpa/inet.h>  // Functions that convert addrinfo member values.
#include <sys/socket.h> //

#include "addrinfo_debug.h"

/****
 * This function is not necessary, but included as a way to
 * document access to the data returned **by getaddrinfo()**.
 */
void display_addrinfo(const struct addrinfo* ai)
{
   const struct addrinfo *pa = ai;

   while (pa)
   {
      struct sockaddr_in *psin = (struct sockaddr_in*)pa->ai_addr;

      /* Due to ambiguous byte ordering of the internet source data,
       * we need to use conversion functions to interpret the data
       * returned from getaddrinfo():
       * For functions inet_ntoa, ntohs and their relatives, the
       * *n* in ntoa and ntohs refers to *net*,
       * "h" in ntohs refers to *host".
       * *a* in ntoa refers to *alpha*, and
       * *s* in ntohs refers to *short* integer.
       * Thinking about these and applying to related function
       * names helps to understand which of the functions are
       * useful in specific situations.
       */

      printf("  Canon Name: %s\n", pa->ai_canonname);
      printf("    ai_flags    = %s\n", aistr_flags(pa->ai_flags));
      printf("    ai_family   = %s\n", aistr_family(pa->ai_family));
      printf("    ai_socktype = %s\n", aistr_socktype(pa->ai_socktype));
      printf("    ai_protocol = %s\n", aistr_protocol(pa->ai_protocol));
      printf("    ai_addrlen  = %d\n", pa->ai_addrlen);
      printf("    Address: %s:%d\n", inet_ntoa(psin->sin_addr), ntohs(psin->sin_port));

      pa = pa->ai_next;
   }
}

// For appending a string to the target, returning the number of characters copied
int copy_str_len(char *target, const char *source, char *buff_start, int buff_len)
{
   int len = strlen(source);

   // Make room for ' | ' if after first flag: 
   if (target > buff_start)
      len += 3;

   // Leave room for terminating \0 ( +1 below ):
   if (target + len + 1 <= buff_start + buff_len)
   {
      if (target > buff_start)
      {
         strcpy(target," | ");
         target += 3;
      }
 
      strcpy(target, source);

      return len;
   }
   else
      fprintf(stderr, "Insufficient space to append addrinfo flag.\n");

   return 0;
}

/**
 * Values harvested from netdb.h
 */
const char *aistr_flags(int ai_flags)
{
   static const char STR_PASSIVE[]                  = "PASSIVE";
   static const char STR_CANONNAME[]                = "CANONNAME";
   static const char STR_NUMERICHOST[]              = "NUMERICHOST";
   static const char STR_V4MAPPED[]                 = "V4MAPPED";
   static const char STR_ALL[]                      = "ALL";
   static const char STR_ADDRCONFIG[]               = "ADDRCONFIG";
#ifdef __USE_GNU
   static const char STR_IDN[]                      = "IDN";
   static const char STR_CANONIDN[]                 = "CANONIDN";
   static const char STR_IDN_ALLOW_UNASSIGNED[]     = "IDN_ALLOW_UNASSIGNED";
   static const char STR_IDN_USE_STD3_ASCII_RULES[] = "IDN_USE_STD3_ASCII_RULES";
#endif
   static const char STR_NUMERICSERV[]              = "NUMERICSERV";

   static char buffer[128];
   int bufflen = sizeof(buffer);
   memset(buffer, 0, bufflen);

   char *bptr = buffer;

   if (ai_flags & AI_PASSIVE)
      bptr += copy_str_len(bptr, STR_PASSIVE, buffer, bufflen);
   
   if (ai_flags & AI_CANONNAME)
      bptr += copy_str_len(bptr, STR_CANONNAME, buffer, bufflen);
   
   if (ai_flags & AI_NUMERICHOST)
      bptr += copy_str_len(bptr, STR_NUMERICHOST, buffer, bufflen);
   
   if (ai_flags & AI_V4MAPPED)
      bptr += copy_str_len(bptr, STR_V4MAPPED, buffer, bufflen);
   
   if (ai_flags & AI_ALL)
      bptr += copy_str_len(bptr, STR_ALL, buffer, bufflen);
   
   if (ai_flags & AI_ADDRCONFIG)
      bptr += copy_str_len(bptr, STR_ADDRCONFIG, buffer, bufflen);
   
#ifdef __USE_GNU
   if (ai_flags & AI_IDN)
      bptr += copy_str_len(bptr, STR_IDN, buffer, bufflen);
   
   if (ai_flags & AI_CANONIDN)
      bptr += copy_str_len(bptr, STR_CANONIDN, buffer, bufflen);
   
   if (ai_flags & AI_IDN_ALLOW_UNASSIGNED)
      bptr += copy_str_len(bptr, STR_IDN_ALLOW_UNASSIGNED, buffer, bufflen);
   
   if (ai_flags & AI_IDN_USE_STD3_ASCII_RULES)
      bptr += copy_str_len(bptr, STR_IDN_USE_STD3_ASCII_RULES, buffer, bufflen);
#endif
   
   if (ai_flags & AI_NUMERICSERV)
      bptr += copy_str_len(bptr, STR_NUMERICSERV, buffer, bufflen);

   bptr = '\0';
   return buffer;
}

/**
 * Values harvested from bits/socket.h
 */
const char *aistr_family(int ai_family)
{
   static const char STR_UNSPEC[] = "UNSPEC";
   static const char STR_LOCAL[] = "LOCAL";
   /* static const char STR_UNIX[] = "UNIX"; */  // UNIX same as LOCAL
   /* static const char STR_FILE[] = "FILE"; */  // FILE same as LOCAL
   static const char STR_INET[] = "INET";
   static const char STR_AX25[] = "AX25";
   static const char STR_IPX[] = "IPX";
   static const char STR_APPLETALK[] = "APPLETALK";
   static const char STR_NETROM[] = "NETROM";
   static const char STR_BRIDGE[] = "BRIDGE";
   static const char STR_ATMPVC[] = "ATMPVC";
   static const char STR_X25[] = "X25";
   static const char STR_INET6[] = "INET6";
   static const char STR_ROSE[] = "ROSE";
   static const char STR_DECnet[] = "DECnet";
   static const char STR_NETBEUI[] = "NETBEUI";
   static const char STR_SECURITY[] = "SECURITY";
   static const char STR_KEY[] = "KEY";
   static const char STR_NETLINK[] = "NETLINK";
   /* static const char STR_ROUTE[] = "ROUTE"; */  // ROUTE same as NETLINK
   static const char STR_PACKET[] = "PACKET";
   static const char STR_ASH[] = "ASH";
   static const char STR_ECONET[] = "ECONET";
   static const char STR_ATMSVC[] = "ATMSVC";
   static const char STR_RDS[] = "RDS";
   static const char STR_SNA[] = "SNA";
   static const char STR_IRDA[] = "IRDA";
   static const char STR_PPPOX[] = "PPPOX";
   static const char STR_WANPIPE[] = "WANPIPE";
   static const char STR_LLC[] = "LLC";
   static const char STR_IB[] = "IB";
   static const char STR_MPLS[] = "MPLS";
   static const char STR_CAN[] = "CAN";
   static const char STR_TIPC[] = "TIPC";
   static const char STR_BLUETOOTH[] = "BLUETOOTH";
   static const char STR_IUCV[] = "IUCV";
   static const char STR_RXRPC[] = "RXRPC";
   static const char STR_ISDN[] = "ISDN";
   static const char STR_PHONET[] = "PHONET";
   static const char STR_IEEE802154[] = "IEEE802154";
   static const char STR_CAIF[] = "CAIF";
   static const char STR_ALG[] = "ALG";
   static const char STR_NFC[] = "NFC";
   static const char STR_VSOCK[] = "VSOCK";
   static const char STR_MAX[] = "MAX";

   switch(ai_family)
   {
      case PF_UNSPEC: return STR_UNSPEC;
      case PF_LOCAL: return STR_LOCAL;
         /* case PF_UNIX: return STR_UNIX; */ // PF_LOCAL == PF_UNIX
         /* case PF_FILE: return STR_FILE; */ // PF_LOCAL == PF_FILE
      case PF_INET: return STR_INET;
      case PF_AX25: return STR_AX25;
      case PF_IPX: return STR_IPX;
      case PF_APPLETALK: return STR_APPLETALK;
      case PF_NETROM: return STR_NETROM;
      case PF_BRIDGE: return STR_BRIDGE;
      case PF_ATMPVC: return STR_ATMPVC;
      case PF_X25: return STR_X25;
      case PF_INET6: return STR_INET6;
      case PF_ROSE: return STR_ROSE;
      case PF_DECnet: return STR_DECnet;
      case PF_NETBEUI: return STR_NETBEUI;
      case PF_SECURITY: return STR_SECURITY;
      case PF_KEY: return STR_KEY;
      case PF_NETLINK: return STR_NETLINK;
         /* case PF_ROUTE: return STR_ROUTE; */  // PF_ROUTE == PF_NETLINK
      case PF_PACKET: return STR_PACKET;
      case PF_ASH: return STR_ASH;
      case PF_ECONET: return STR_ECONET;
      case PF_ATMSVC: return STR_ATMSVC;
      case PF_RDS: return STR_RDS;
      case PF_SNA: return STR_SNA;
      case PF_IRDA: return STR_IRDA;
      case PF_PPPOX: return STR_PPPOX;
      case PF_WANPIPE: return STR_WANPIPE;
      case PF_LLC: return STR_LLC;
      case PF_IB: return STR_IB;
      case PF_MPLS: return STR_MPLS;
      case PF_CAN: return STR_CAN;
      case PF_TIPC: return STR_TIPC;
      case PF_BLUETOOTH: return STR_BLUETOOTH;
      case PF_IUCV: return STR_IUCV;
      case PF_RXRPC: return STR_RXRPC;
      case PF_ISDN: return STR_ISDN;
      case PF_PHONET: return STR_PHONET;
      case PF_IEEE802154: return STR_IEEE802154;
      case PF_CAIF: return STR_CAIF;
      case PF_ALG: return STR_ALG;
      case PF_NFC: return STR_NFC;
      case PF_VSOCK: return STR_VSOCK;
      case PF_MAX: return STR_MAX;
      default: return "Unknown family";
   }
}

/**
 * Values harvested from bits/socket_type.h
 */
const char *aistr_socktype(int ai_socktype)
{
   static const char STR_STREAM[] = "STREAM";
   static const char STR_DGRAM[] = "DGRAM";
   static const char STR_RAW[] = "RAW";
   static const char STR_RDM[] = "RDM";
   static const char STR_SEQPACKET[] = "SEQPACKET";
   static const char STR_DCCP[] = "DCCP";
   static const char STR_PACKET[] = "PACKET";
   static const char STR_CLOEXEC[] = "CLOEXEC";
   static const char STR_NONBLOCK[] = "NONBLOCK";

   switch(ai_socktype)
   {
      case SOCK_STREAM: return STR_STREAM;
      case SOCK_DGRAM: return STR_DGRAM;
      case SOCK_RAW: return STR_RAW;
      case SOCK_RDM: return STR_RDM;
      case SOCK_SEQPACKET: return STR_SEQPACKET;
      case SOCK_DCCP: return STR_DCCP;
      case SOCK_PACKET: return STR_PACKET;
      case SOCK_CLOEXEC: return STR_CLOEXEC;
      case SOCK_NONBLOCK: return STR_NONBLOCK;
      default: return "Unknown socket type";
   }
}

/**
 * Values harvested from netinet/in.h
 */
const char *aistr_protocol(int ai_protocol)
{
   static const char STR_IP[] = "IP";
   static const char STR_ICMP[] = "ICMP";
   static const char STR_IGMP[] = "IGMP";
   static const char STR_IPIP[] = "IPIP";
   static const char STR_TCP[] = "TCP";
   static const char STR_EGP[] = "EGP";
   static const char STR_PUP[] = "PUP";
   static const char STR_UDP[] = "UDP";
   static const char STR_IDP[] = "IDP";
   static const char STR_TP[] = "TP";
   static const char STR_DCCP[] = "DCCP";
   static const char STR_IPV6[] = "IPV6";
   static const char STR_RSVP[] = "RSVP";
   static const char STR_GRE[] = "GRE";
   static const char STR_ESP[] = "ESP";
   static const char STR_AH[] = "AH";
   static const char STR_MTP[] = "MTP";
   static const char STR_BEETPH[] = "BEETPH";
   static const char STR_ENCAP[] = "ENCAP";
   static const char STR_PIM[] = "PIM";
   static const char STR_COMP[] = "COMP";
   static const char STR_SCTP[] = "SCTP";
   static const char STR_UDPLITE[] = "UDPLITE";
   static const char STR_MPLS[] = "MPLS";
   static const char STR_RAW[] = "RAW";

   switch(ai_protocol)
   {
      case IPPROTO_IP: return STR_IP;
      case IPPROTO_ICMP: return STR_ICMP;
      case IPPROTO_IGMP: return STR_IGMP;
      case IPPROTO_IPIP: return STR_IPIP;
      case IPPROTO_TCP: return STR_TCP;
      case IPPROTO_EGP: return STR_EGP;
      case IPPROTO_PUP: return STR_PUP;
      case IPPROTO_UDP: return STR_UDP;
      case IPPROTO_IDP: return STR_IDP;
      case IPPROTO_TP: return STR_TP;
      case IPPROTO_DCCP: return STR_DCCP;
      case IPPROTO_IPV6: return STR_IPV6;
      case IPPROTO_RSVP: return STR_RSVP;
      case IPPROTO_GRE: return STR_GRE;
      case IPPROTO_ESP: return STR_ESP;
      case IPPROTO_AH: return STR_AH;
      case IPPROTO_MTP: return STR_MTP;
      case IPPROTO_BEETPH: return STR_BEETPH;
      case IPPROTO_ENCAP: return STR_ENCAP;
      case IPPROTO_PIM: return STR_PIM;
      case IPPROTO_COMP: return STR_COMP;
      case IPPROTO_SCTP: return STR_SCTP;
      case IPPROTO_UDPLITE: return STR_UDPLITE;
      case IPPROTO_MPLS: return STR_MPLS;
      case IPPROTO_RAW: return STR_RAW;
      default: return "Unknown protocol";
   }
}
