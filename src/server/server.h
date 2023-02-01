#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

typedef struct {
	char addr[MAX_USER_ADDR];
	char name[MAX_REFNAME];
	int sd;
	int id;
	bool is_admin;
	bool heartbeat_started;

	pthread_mutex_t out_lock;
	char *outbound_buf;
	int outbound_len;

	SSL *ssl;
	sqlite3 *db;
	int thread_id;
} conn_t;

typedef struct {
	conn_t conns[MAX_CONNS];
	int num_conns;
	pthread_mutex_t conn_lock;
	_Atomic int thread_count;

	char *hkey;
	time_t boot_time;
	bool running;
} engine_state_t;

// these live in commands.c, but don't really justify their own header
int process_inbound(engine_state_t *, conn_t *, char *, int, token_t *, int *);
int dispatch_command(engine_state_t *, conn_t *, token_t *, int);

void send_targeted_conn_response(int status, conn_t *conn, char *from, char *msg);
void send_conn_response(int status, conn_t *conn, char *msg);
void send_conn_raw(conn_t *conn, char *msg);

static void pdump(char *msg) {
	perror(msg);
	exit(1);
}

// Makes clang less whiny about security with str[] -> char * typecasts.
static void pwrap(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	puts("");
}

#define panic(...) do { printf("{%s -- (%s:%d)} ", __func__, __FILE__, __LINE__); pwrap(__VA_ARGS__); exit(1); } while (0);
#define here() do { printf("HERE @ {%s -- (%s:%d)}\n", __func__, __FILE__, __LINE__); } while (0);

static char *gm_timestr(time_t t, char *buf, int len) {
	struct tm *cur_time = gmtime(&t);

	if (!strftime(buf, len, "%Y-%m-%d %H:%M:%S", cur_time)) {
		return NULL;
	}

	return buf;
}

#endif
