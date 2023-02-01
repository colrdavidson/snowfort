#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <signal.h>

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../comms.h"
#include "server.h"
#include "db.h"

#define MAX_EVENTS 10
#define MAX_TIMEOUT 10
#define MAX_TIMEOUT_MS (MAX_TIMEOUT * 1000)
#define MAX_HEARTBEAT 10
#define MAX_HEARTBEAT_MS (MAX_HEARTBEAT * 1000)
#define LISTEN_PORT 9253
#define MAX_CONN_QUEUE 10
#define LISTEN_PORT 9253

engine_state_t engine;

void exit_handler(int sig) {
	if (engine.running) {
		printf("Shutting down the server!\n");
		engine.running = false;
	} else {
		printf("Force-quitting!\n");
		exit(1);
	}
}

typedef struct {
	engine_state_t *engine;
	SSL_CTX *ssl_ctx;
	char addr[INET6_ADDRSTRLEN];
	int sock;
	int id;
} thread_ctx_t;

static char *file_to_string(const char *filename) {
	FILE *file = fopen(filename, "r");

	if (file == NULL) {
		printf("%s not found!\n", filename);
		return NULL;
	}

	fseek(file, 0, SEEK_END);
	size_t len = ftell(file);
	fseek(file, 0, SEEK_SET);

	char *file_str = (char *)malloc(len + 1);
	len = fread(file_str, 1, len, file);
	file_str[len] = 0;

	fclose(file);
	return file_str;
}

int add_conn(engine_state_t *engine, int thread_id, int sock, char *addr, SSL_CTX *ctx) {
	pthread_mutex_lock(&engine->conn_lock);

	int i = 0;
	for (; i < MAX_CONNS; i++) {
		if (engine->conns[i].thread_id == -1) {
			break;
		}
	}

	if (i == MAX_CONNS) {
		printf("Full up on conns!\n");
		pthread_mutex_unlock(&engine->conn_lock);
		return -1;
	}
	engine->conns[i].thread_id = thread_id;
	engine->conns[i].id = -1;
	pthread_mutex_unlock(&engine->conn_lock);

	sqlite3 *db;
	open_db(&db);

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);

	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	engine->conns[i].sd = sock;
	engine->conns[i].ssl = ssl;

	engine->conns[i].db = db;
	engine->conns[i].heartbeat_started = false;
	memset(engine->conns[i].name, 0, MAX_REFNAME);
	sprintf(engine->conns[i].addr, "%s", addr);

	printf("connected thread %d, socket %d from %s\n", thread_id, sock, engine->conns[i].addr);

	return i;
}

void close_conn(engine_state_t *engine, int thread_id) {
	pthread_mutex_lock(&engine->conn_lock);

	int i = 0;
	for (; i < MAX_CONNS; i++) {
		if (engine->conns[i].thread_id == thread_id) {
			break;
		}
	}
	if (i == MAX_CONNS) {
		printf("conn not found!\n");
		pthread_mutex_unlock(&engine->conn_lock);
		return;
	}
	printf("disconnected thread %d, socket %d from %s\n", thread_id, engine->conns[i].sd, engine->conns[i].addr);

	engine->conns[i].thread_id = -1;

	SSL_shutdown(engine->conns[i].ssl);
	close(engine->conns[i].sd);
	SSL_free(engine->conns[i].ssl);

	engine->conns[i].sd = -1;
	engine->conns[i].ssl = NULL;
	engine->conns[i].outbound_len = 0;

	pthread_mutex_unlock(&engine->conn_lock);

}

void *thread_main(void *passed_ctx) {
	// Yoinking the passed context off the global heap so we don't have to remember to free it later
	thread_ctx_t thread_ctx;
	memcpy(&thread_ctx, passed_ctx, sizeof(thread_ctx_t));
	free(passed_ctx);
	thread_ctx.engine->thread_count += 1;

	char in_buffer[MAX_IN_BUFFER];

	struct timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	setsockopt(thread_ctx.sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

	int conn_idx = add_conn(thread_ctx.engine, thread_ctx.id, thread_ctx.sock, thread_ctx.addr, thread_ctx.ssl_ctx);
	if (conn_idx == -1) {
		goto thread_exit;
	}
	conn_t *conn = &thread_ctx.engine->conns[conn_idx];

	while (thread_ctx.engine->running) {
		int ret_bytes = 0;
		ret_bytes = SSL_read(conn->ssl, in_buffer, MAX_IN_BUFFER);
		if (ret_bytes == 0) {
			close_conn(thread_ctx.engine, thread_ctx.id);
			printf("client closed the connection!\n");
			goto thread_exit;
		} else if (ret_bytes == -1) {
			if (conn->heartbeat_started) {
				close_conn(thread_ctx.engine, thread_ctx.id);
				printf("client failed to yeet!\n");
				goto thread_exit;
			}

			conn->heartbeat_started = true;
			send_conn_raw(conn, "\\toss\n");
		} else {
			conn->heartbeat_started = false;
		}

		int off = 0;
		while (off < ret_bytes) {
			token_t toks[MAX_TOKS] = {0};
			int toks_found = 0;
			int ret = process_inbound(thread_ctx.engine, conn, in_buffer + off, ret_bytes - off, toks, &toks_found);
			if (ret == -1) {
				break;
			}

			off += ret;

			if (toks_found > 0) {
				ret = dispatch_command(thread_ctx.engine, conn, toks, toks_found);
				if (ret == -1) {
					// Got a bad command, not bothering with the rest of the buffer
					break;
				}
			}
		}

		pthread_mutex_lock(&conn->out_lock);
/*
		if (conn->outbound_len > 0) {
			printf("SENDING: %.*s", conn->outbound_len, conn->outbound_buf);
		}
*/

		int send_size = SSL_write(conn->ssl, conn->outbound_buf, conn->outbound_len);
		if (send_size > 0) {
			conn->outbound_len -= send_size;
		}
		pthread_mutex_unlock(&conn->out_lock);
	}

thread_exit:
	thread_ctx.engine->thread_count -= 1;
	return 0;
}

int main(int argc, char *argv[]) {
	struct sigaction sa = {0};
	sa.sa_handler = exit_handler;
	sigaction(SIGINT, &sa, NULL);

	memset(&engine, 0, sizeof(engine_state_t));
	engine.boot_time = time(NULL);

	char now_buf[80];
	gm_timestr(engine.boot_time, now_buf, sizeof(now_buf));
	printf("Server started at: %s\n", now_buf);

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_crypto_strings();

	engine.hkey = file_to_string("tmp_ssl/hmac_key");
	if (!engine.hkey) {
		panic("Failed to load key file. Try running gen_crypto.sh first\n");
	}

	for (int i = 0; i < MAX_CONNS; i++) {
		engine.conns[i].id = -1;
		engine.conns[i].thread_id = -1;
		pthread_mutex_init(&engine.conns[i].out_lock, NULL);
		engine.conns[i].outbound_buf = malloc(MAX_OUT_BUFFER);
		engine.conns[i].outbound_len = 0;
	}

	pthread_mutex_init(&engine.conn_lock, NULL);

	int randfd = open("/dev/urandom", O_RDONLY);
	setup_database(randfd);

	SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
	if (!ctx) {
		panic("Unable to create SSL context\n");
	}

	if (SSL_CTX_use_certificate_file(ctx, "tmp_ssl/comms_cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return 1;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx,  "tmp_ssl/comms_key.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return 1;
	}

	if (SSL_CTX_check_private_key(ctx) <= 0) {
		ERR_print_errors_fp(stderr);
		return 1;
	}

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

	int listen_sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (listen_sock < 0) {
		pdump("failed opening socket");
	}

	int tmp = 1;
	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&tmp, sizeof(int));

	struct sockaddr_in6 serveraddr = {0};
	serveraddr.sin6_family = AF_INET6;
	serveraddr.sin6_port = htons(LISTEN_PORT);
	serveraddr.sin6_addr = in6addr_any;

	if (bind(listen_sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) > 0) {
		pdump("failed on bind");
	}

	if (listen(listen_sock, MAX_CONN_QUEUE) < 0) {
		pdump("failed on listen");
	}

	printf("Started server on port %d\n", LISTEN_PORT);

	int i = 0;
	engine.running = true;
	while (engine.running) {
		struct sockaddr_in6 addr;
		socklen_t addrlen = sizeof(addr);
		int conn_sock = accept(listen_sock, (struct sockaddr *)&addr, &addrlen);
		if (conn_sock == -1) {
			continue;
		}

		// Handling new connection
		char buf[INET6_ADDRSTRLEN] = {0};
		inet_ntop(AF_INET6, (void *)&addr.sin6_addr, buf, addrlen);

		// This lives on the heap temporarily so we don't accidentally clobber it with another connection
		thread_ctx_t *thread_ctx = malloc(sizeof(thread_ctx_t));
		thread_ctx->engine = &engine;
		thread_ctx->ssl_ctx = ctx;
		thread_ctx->sock = conn_sock;
		thread_ctx->id = i++;
		memcpy(thread_ctx->addr, buf, INET6_ADDRSTRLEN);

		pthread_t thread;
		int ret = pthread_create(&thread, NULL, &thread_main, (void *)thread_ctx);
		pthread_detach(thread);
	}

	printf("waiting for %d children to die!\n", engine.thread_count);
	while (engine.thread_count > 0) {
		sleep(1);
	}

	return 0;
}
