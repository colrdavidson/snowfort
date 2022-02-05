#include "../comms.h"
#include "server.h"

static int add_to_outbound(conn_t *conn, char *buf, int size) {
	pthread_mutex_lock(&conn->out_lock);
	if ((conn->outbound_len + size) > MAX_OUT_BUFFER) {
		pthread_mutex_unlock(&conn->out_lock);
		return 0;
	}

	memcpy(conn->outbound_buf + conn->outbound_len, buf, size);
	conn->outbound_len += size;
	pthread_mutex_unlock(&conn->out_lock);

	return size;
}

void send_targeted_conn_response(int status, conn_t *conn, char *from, char *msg) {
	char out_buffer[MAX_OUT_BUFFER] = {0};
	time_t now = time(NULL);

	int send_bytes = sprintf(out_buffer, "%d %ld %s %s", status, now, from, msg);

	add_to_outbound(conn, out_buffer, send_bytes);
	return;
}

void send_conn_response(int status, conn_t *conn, char *msg) {
	char out_buffer[MAX_OUT_BUFFER] = {0};
	time_t now = time(NULL);

	int send_bytes;
	if (conn->name[0] != '\0') {
		send_bytes = sprintf(out_buffer, "%d %ld %s %s", status, now, conn->name, msg);
	} else {
		send_bytes = sprintf(out_buffer, "%d %ld \\%s %s", status, now, conn->addr, msg);
	}

	add_to_outbound(conn, out_buffer, send_bytes);
	return;
}

void send_conn_raw(conn_t *conn, char *msg) {
	char out_buffer[MAX_OUT_BUFFER] = {0};

	int send_bytes = sprintf(out_buffer, "%s", msg);

	add_to_outbound(conn, out_buffer, send_bytes);
	return;
}
