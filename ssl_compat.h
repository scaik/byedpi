#ifndef SSL_COMPAT_H
#define SSL_COMPAT_H

#include <openssl/ssl.h>

extern const SSL_METHOD *(*TLS_method_fn)(void);
extern SSL_CTX *(*SSL_CTX_new_fn)(const SSL_METHOD*);
extern SSL_CTX *(*SSL_CTX_new_fn)(const SSL_METHOD*);
extern SSL *(*SSL_new_fn)(SSL_CTX*);
extern void *(*SSL_free_fn)(SSL*);
extern int (*SSL_set_fd_fn)(SSL*, int);
extern int (*SSL_connect_fn)(SSL*);
extern int (*SSL_read_fn)(SSL*, void*, int);
extern int (*SSL_write_fn)(SSL*, const void*, int);

int ssl_load(void);

#endif
