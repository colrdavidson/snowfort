#include "../comms.h"
#include "client.h"

#define COMMS_DEBUG
#ifdef COMMS_DEBUG
#define COMMS_PRINT(...) printf(__VA_ARGS__)
#else
#define COMMS_PRINT(...)
#endif

sslstatus_t get_sslstatus(SSL *ssl, int n) {
	switch (SSL_get_error(ssl, n)) {
		case SSL_ERROR_NONE:
			return SSLSTATUS_OK;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			return SSLSTATUS_WANT_IO;
		case SSL_ERROR_ZERO_RETURN:
		case SSL_ERROR_SYSCALL:
		default:
			return SSLSTATUS_FAIL;
	}
}

void send_unencrypted_bytes(conn_t *conn, char *buf, size_t len) {
	conn->encrypt_buf = (char *)realloc(conn->encrypt_buf, conn->encrypt_len + len);
	memcpy(conn->encrypt_buf + conn->encrypt_len, buf, len);
	conn->encrypt_len += len;
}

void queue_encrypted_bytes(conn_t *conn, char *buf, size_t len) {
	conn->write_buf = (char *)realloc(conn->write_buf, conn->write_len + len);
	memcpy(conn->write_buf + conn->write_len, buf, len);
	conn->write_len += len;
}

int do_ssl_handshake(conn_t *conn) {
	char buf[MAX_IN_BUFFER];

	int ret = SSL_do_handshake(conn->ssl);
	sslstatus_t status = get_sslstatus(conn->ssl, ret);
	if (status == SSLSTATUS_FAIL) {
		//ERR_print_errors_fp(stderr);
		return SSLSTATUS_FAIL;
	}

	if (status == SSLSTATUS_WANT_IO) {
		do {
			ret = BIO_read(conn->wbio, buf, sizeof(buf));
			if (ret > 0) {
				queue_encrypted_bytes(conn, buf, ret);
			} else if (!BIO_should_retry(conn->wbio)) {
				return SSLSTATUS_FAIL;
			}
		} while (ret > 0);
	}

	return status;
}

int send_data(conn_t *conn) {
	if (conn->write_len == 0) {
		return 0;
	}

	int ret = send(conn->sd, conn->write_buf, conn->write_len, 0);
	if (ret > 0) {
		if ((size_t)ret < conn->write_len) {
			memmove(conn->write_buf, conn->write_buf + ret, conn->write_len - ret);
		}

		conn->write_len -= ret;
		conn->write_buf = (char *)realloc(conn->write_buf, conn->write_len);
		return 0;
	}

	return -1;
}

int read_data(conn_t *conn, char *src, size_t len, char *dst, size_t *dst_len) {
	char buf[MAX_IN_BUFFER] = {0};
	int ret;
	sslstatus_t status;

	size_t dst_size = *dst_len;
	*dst_len = -1;

	size_t read_size = 0;
	while (len > 0) {
		ret = BIO_write(conn->rbio, src, len);

		if (ret <= 0) {
			return -1;
		}

		src += ret;
		len -= ret;

		if (!SSL_is_init_finished(conn->ssl)) {
			if (do_ssl_handshake(conn) == SSLSTATUS_FAIL) {
				return -1;
			}

			if (!SSL_is_init_finished(conn->ssl)) {
				return 0;
			}
		}

		do {
			ret = SSL_read(conn->ssl, buf, sizeof(buf));
			if (ret > 0) {
				if ((read_size + ret) > MAX_IN_BUFFER) {
					printf("Trying to stuff too much into inbuffer\n");
					return -1;
				}

				memcpy(dst + read_size, buf, ret);
				read_size += ret;
			}
		} while (ret > 0);

		status = get_sslstatus(conn->ssl, ret);
		if (status == SSLSTATUS_WANT_IO) {
			do {
				ret = BIO_read(conn->wbio, buf, sizeof(buf));
				if (ret > 0) {
					queue_encrypted_bytes(conn, buf, ret);
				} else if (!BIO_should_retry(conn->wbio)) {
					return -1;
				}
			} while (ret > 0);
		}

		if (status == SSLSTATUS_FAIL) {
			return -1;
		}
	}

	*dst_len = read_size;
	return 0;
}

int encrypt_data(conn_t *conn) {
	char buf[MAX_IN_BUFFER];

	if (!SSL_is_init_finished(conn->ssl)) {
		return 0;
	}

	while (conn->encrypt_len > 0) {
		int ret = SSL_write(conn->ssl, conn->encrypt_buf, conn->encrypt_len);
		sslstatus_t status = get_sslstatus(conn->ssl, ret);

		if (ret > 0) {
			if ((size_t)ret < conn->encrypt_len) {
				memmove(conn->encrypt_buf, conn->encrypt_buf + ret, conn->encrypt_len - ret);
			}

			conn->encrypt_len -= ret;
			conn->encrypt_buf = (char *)realloc(conn->encrypt_buf, conn->encrypt_len);

			do {
				ret = BIO_read(conn->wbio, buf, sizeof(buf));
				if (ret > 0) {
					queue_encrypted_bytes(conn, buf, ret);
				} else if (!BIO_should_retry(conn->wbio)) {
					return -1;
				}
			} while (ret > 0);
		}

		if (status == SSLSTATUS_FAIL) {
			return -1;
		}

		if (ret == 0) {
			break;
		}
	}

	return 0;
}

void send_targeted_conn_response(int status, conn_t *conn, char *from, char *msg) {
	char out_buffer[MAX_OUT_BUFFER + 1] = {0};
	time_t now = time(NULL);

	int send_bytes = sprintf(out_buffer, "%d %ld %s %s", status, now, from, msg);
	COMMS_PRINT("SENDING: %s", out_buffer);

	send_unencrypted_bytes(conn, out_buffer, send_bytes);

	encrypt_data(conn);
	send_data(conn);

	return;
}

void send_conn_response(int status, conn_t *conn, char *msg) {
	char out_buffer[MAX_OUT_BUFFER + 1] = {0};
	time_t now = time(NULL);

	int send_bytes;
	if (conn->name[0] != '\0') {
		send_bytes = sprintf(out_buffer, "%d %ld %s %s", status, now, conn->name, msg);
	} else {
		send_bytes = sprintf(out_buffer, "%d %ld \\%s %s", status, now, conn->addr, msg);
	}

	COMMS_PRINT("SENDING: %s", out_buffer);

	send_unencrypted_bytes(conn, out_buffer, send_bytes);

	encrypt_data(conn);
	send_data(conn);

	return;
}

void send_conn_raw(conn_t *conn, char *msg) {
	char out_buffer[MAX_OUT_BUFFER + 1] = {0};

	int send_bytes = sprintf(out_buffer, "%s", msg);
	COMMS_PRINT("SENDING: %s", out_buffer);

	send_unencrypted_bytes(conn, out_buffer, send_bytes);

	encrypt_data(conn);
	send_data(conn);

	return;
}
