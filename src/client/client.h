#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <sqlite3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct {
	char addr[MAX_USER_ADDR];
	char name[MAX_REFNAME];
	struct timespec last_checkin;
	struct timespec heartbeat_started;
	int sd;
	int id;
	bool is_admin;

	SSL *ssl;
	BIO *rbio;
	BIO *wbio;
	char *write_buf;
	size_t write_len;
	char *encrypt_buf;
	size_t encrypt_len;
} conn_t;

typedef enum { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL} sslstatus_t;

sslstatus_t get_sslstatus(SSL *ssl, int n);
void send_unencrypted_bytes(conn_t *conn, char *buf, size_t len);
void queue_encrypted_bytes(conn_t *conn, char *buf, size_t len);
int do_ssl_handshake(conn_t *conn);
int send_data(conn_t *conn);
int read_data(conn_t *conn, char *src, size_t len, char *dst, size_t *dst_len);
int encrypt_data(conn_t *conn);

void send_targeted_conn_response(int status, conn_t *conn, char *from, char *msg);
void send_conn_response(int status, conn_t *conn, char *msg);
void send_conn_raw(conn_t *conn, char *msg);

#endif
