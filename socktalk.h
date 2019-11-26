#include <sys/types.h>

#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/bio.h>

struct _stalker;

typedef size_t (*SockWriter)(const struct _stalker*, const void *data, int data_len);
typedef size_t (*SockReader)(const struct _stalker*, void *buffer, int buff_len);

size_t stk_sock_talker(const struct _stalker* talker, const void *data, int data_len);
size_t stk_ssl_talker(const struct _stalker* talker, const void *data, int data_len);

size_t stk_sock_reader(const struct _stalker* talker, void *buffer, int buff_len);
size_t stk_ssl_reader(const struct _stalker* talker, void *buffer, int buff_len);

/**
 * @brief Linked-list structure for preserving results of a socket read.
 */
typedef struct _status_line
{
   int  status;
   const char *message;
   struct _status_line *next;
} Status_Line;


typedef struct _stalker
{
   SSL*       ssl_handle;       // pointer to socket handle OR SSH structure
   int        socket_handle;
   SockWriter writer;
   SockReader reader;
   
} STalker;

/** STalker initialization functions to prepare STalker to call send_line, recv_line. */
void init_ssh_talker(struct _stalker* talker, SSL* ssl);
void init_sock_talker(struct _stalker* talker, int socket);


/**
 * Functions that actually read or write using the STalker object.
 */
size_t stk_send_line(const struct _stalker* talker, ...);
size_t stk_recv_line(const struct _stalker* talker, void *buffer, int buff_len);


int walk_status_reply(const char *str, int *status, const char** line, int *line_len);

int seek_status_message(const struct _status_line* sl, const char *value);
