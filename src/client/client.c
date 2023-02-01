#ifdef __APPLE__
#define _XOPEN_SOURCE_EXTENDED
#elif __linux
#define _GNU_SOURCE
#endif


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <locale.h>
#include <wchar.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <ncurses.h>

#include "../comms.h"
#include "client.h"

#define MAX_HISTORY 100

#define CTRL(x) ((x) & 0x1f)
#define isutf8_head(c) (((c) & 0xC0) != 0x80)

//#define NO_CURSES

typedef struct {
	wchar_t c;
	int sz;
	int colsz;
} wide_ref_t;

// maintain these two together because otherwise O(n) is a PITA
typedef struct {
	wide_ref_t wbuf[MAX_MESSAGE_LEN];
	int wlen;

	char cbuf[MAX_MESSAGE_LEN];
	int clen;
} cmd_buf_t;

typedef struct {
	uint64_t id;
	char data[MAX_MESSAGE_LEN];
	int len;
	time_t sent;
} micro_msg_t;

typedef struct {
	micro_msg_t msg;
	int sender_id;
} channel_msg_t;

typedef struct {
	micro_msg_t msg;
	bool am_sender;
} private_msg_t;

typedef struct {
	char name[MAX_REFNAME];
	int unread_count;
	bool has_pmd;
	bool is_live;
} userref_t;

typedef struct {
	channel_msg_t messages[MAX_HISTORY];
	int msgs_len;

	int users[MAX_CHANNEL_USERS];
	int users_len;

	char name[MAX_REFNAME];
	bool joined;
	int unread_count;
} channel_history_t;

typedef struct {
	private_msg_t messages[MAX_HISTORY];
	int msgs_len;

	int other_id;
} pm_history_t;

typedef enum {
	VIEW_CHANNEL,
	VIEW_PM,
	VIEW_INTERNAL
} view_t;

typedef struct {
	channel_history_t *channel_hist;
	int channels_len;
	int max_channels;

	pm_history_t *private_hist;
	int pms_len;
	int max_pms;

	userref_t *users;
	int users_len;
	int max_users;

	char auth_token[MAX_B64_AUTH_TOKEN + 1];
	char name[MAX_REFNAME + 1];
	int user_id;

	int view_id;
	view_t view_type;

	bool has_ip;
	char ip_addr[INET6_ADDRSTRLEN];
	uint16_t port;
	SSL_CTX *ctx;
	bool verified_server_cert;
	conn_t conn;
} client_state_t;

int retry_count = 0;

char encrypted_in_buffer[MAX_IN_BUFFER + 1] = {0};
char clear_in_buffer[MAX_IN_BUFFER + 1] = {0};

char error_buffer[MAX_MESSAGE_LEN] = {0};
bool has_error = false;

cmd_buf_t *cmd_scrollback_buffer;
int cmd_scrollback_len = 1;
int cmd_scrollback_idx = 0;

char **internal_scrollback_buffer;
int internal_scrollback_len = 0;
char **page_scrollback_buffer;
int page_scrollback_len = 0;
int scrollback_max = MAX_HISTORY;
time_t dateline = 0;


int max_term_row, max_term_col;
int max_chat_row, max_chat_col;
int max_meta_row, max_meta_col;

int cur_row = 0;
int cur_col = 0;
int cur_wchar = 0;

bool root_killme = false;
bool window_resized = false;
bool redraw = false;

WINDOW *chat_win = NULL;
WINDOW *meta_win = NULL;

int log_file = 0;

inline static void pdump(char *msg) {
	endwin();

	perror(msg);
	exit(1);
}

inline static void panic(const char *fmt, ...) {
	endwin();

	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	exit(1);
}

#define log(...) if (log_file) { dprintf(log_file, __VA_ARGS__); }

void int_handler(int blah) {
	root_killme = true;
}

void push_to_scrollback(char **scrollback_buffer, int *scrollback_len, char *buffer) {
	int len = *scrollback_len;

	// This is a pointer ring buffer. We never free any pointers,
	// we just reuse the pointer for the oldest message when making room for our newest message
	if (len == scrollback_max) {
		char *tail = scrollback_buffer[0];
		memset(tail, 0, MAX_MESSAGE_LEN);

		memmove(&scrollback_buffer[0], &scrollback_buffer[1], sizeof(char *) * (len - 1));
		scrollback_buffer[len - 1] = tail;

		len--;
	}

	strcpy(scrollback_buffer[len++], buffer);
	*scrollback_len = len;

	redraw = true;
}

void flush_scrollback(char **scrollback_buffer, int *scrollback_len) {
	int len = *scrollback_len;

	for (int i = 0; i < len; i++) {
		memset(scrollback_buffer[i], 0, MAX_MESSAGE_LEN);
	}

	*scrollback_len = 0;
	dateline = 0;
	redraw = true;
}

void print_line_time(time_t now, const char *fmt, ...) {
	char line_buffer[MAX_MESSAGE_LEN] = {0};

	va_list args;
	va_start(args, fmt);
	vsprintf(line_buffer, fmt, args);
	va_end(args);


	// dateline not printed, or at least 1 day past the last dateline
	if (!dateline || now > (dateline + 86400)){
		char tmp[MAX_MESSAGE_LEN] = {0};
		char curtime[80];

		struct tm *tmpts = localtime(&now); // datetime should be from midnight-to-midnight
		tmpts->tm_hour = 0;
		tmpts->tm_min = 0;
		tmpts->tm_sec = 0;
		dateline = mktime(tmpts);

		int ret_size = strftime(curtime, sizeof(curtime), "%a %Y-%m-%d %Z", tmpts);
		sprintf(tmp, "%s", curtime);
		push_to_scrollback(page_scrollback_buffer, &page_scrollback_len, tmp);
	}

	struct tm *nowts = localtime(&now);
	char tmp[MAX_MESSAGE_LEN] = {0};
	char curtime[80];

	int ret_size = strftime(curtime, sizeof(curtime), "%H:%M:%S", nowts);
	int indent = 9 - ret_size;
	sprintf(tmp, "%s%*s| %s", curtime, indent, "", line_buffer);
	push_to_scrollback(page_scrollback_buffer, &page_scrollback_len, tmp);
}

void print_line(const char *fmt, ...) {
	char line_buffer[MAX_MESSAGE_LEN] = {0};
	char tmp[MAX_MESSAGE_LEN] = {0};

	va_list args;
	va_start(args, fmt);
	vsprintf(line_buffer, fmt, args);
	va_end(args);

	char curtime[80];
	time_t now = time(NULL);
	struct tm *nowts = localtime(&now);
	int ret_size = strftime(curtime, sizeof(curtime), "%a %Y-%m-%d %H:%M:%S %Z", nowts);

	int indent = 29 - ret_size;
	sprintf(tmp, "%s%*s| %s", curtime, indent, "", line_buffer);
	push_to_scrollback(page_scrollback_buffer, &page_scrollback_len, tmp);
}

void print_line_internal(const char *fmt, ...) {
	char line_buffer[MAX_MESSAGE_LEN] = {0};
	char tmp[MAX_MESSAGE_LEN] = {0};

	va_list args;
	va_start(args, fmt);
	vsprintf(line_buffer, fmt, args);
	va_end(args);

	sprintf(tmp, "|> %s", line_buffer);
	log("%s", tmp);
	push_to_scrollback(internal_scrollback_buffer, &internal_scrollback_len, tmp);
}

void print_line_error(const char *fmt, ...) {
	char line_buffer[MAX_MESSAGE_LEN] = {0};

	va_list args;
	va_start(args, fmt);
	vsprintf(line_buffer, fmt, args);
	va_end(args);

	memset(error_buffer, 0, sizeof(error_buffer));
	sprintf(error_buffer, "ERROR: %s\n", line_buffer);

	has_error = true;
	redraw = true;
}


void send_to_conn_raw(conn_t *conn, char *buf, size_t len) {
	if (conn->sd == -1) {
		return;
	}

	send_unencrypted_bytes(conn, buf, len);
	encrypt_data(conn);
	send_data(conn);
}

void send_to_conn(client_state_t *client, char *buf, int len) {
	char tmp[MAX_OUT_BUFFER] = {0};
	int n = sprintf(tmp, "%s %.*s", client->auth_token, len, buf);
	// print_line_internal("SENDING: %.*s", n, tmp);
	send_to_conn_raw(&client->conn, tmp, n);
}

void batch_to_conn(client_state_t *client, token_t *lines, int num_lines) {
	char tmp[MAX_OUT_BUFFER] = {0};
	int n = 0;
	for (int i = 0; i < num_lines; i++) {
		int ret = snprintf(tmp + n, MAX_OUT_BUFFER - n, "%s %.*s",
			client->auth_token, lines[i].size, lines[i].ptr);
		if (ret == 0) {
			panic("No more space in batch buffer!\n");
		}
		n += ret;
	}

	// print_line_internal("SENDING: %.*s", n, tmp);
	send_to_conn_raw(&client->conn, tmp, n);
}

void push_to_cmd_scrollback(cmd_buf_t *cmd_buf) {
	// Deliberately leaving the 0th element in the list alone, as it's our default keybuffer

	if (cmd_scrollback_len == scrollback_max) {
		cmd_buf_t *tail = &cmd_scrollback_buffer[1];
		memset(tail, 0, sizeof(cmd_buf_t));

		memmove(&cmd_scrollback_buffer[1], &cmd_scrollback_buffer[2], sizeof(cmd_buf_t) * (cmd_scrollback_len - 2));
		memcpy(&cmd_scrollback_buffer[cmd_scrollback_len - 1], tail, sizeof(cmd_buf_t));

		cmd_scrollback_len--;
	}

	memcpy(cmd_scrollback_buffer[cmd_scrollback_len].cbuf, cmd_buf->cbuf, cmd_buf->clen);
	cmd_scrollback_buffer[cmd_scrollback_len].clen = cmd_buf->clen;
	memcpy(cmd_scrollback_buffer[cmd_scrollback_len].wbuf, cmd_buf->wbuf, sizeof(wide_ref_t) * cmd_buf->wlen);
	cmd_scrollback_buffer[cmd_scrollback_len].wlen = cmd_buf->wlen;

	cmd_scrollback_len++;
}

int tokenize_buffer(client_state_t *client, bool user_input, char *buffer, int len, token_t *toks, int *toks_len) {
	conn_t *conn = &client->conn;

	int clear_off = 0;
	*toks_len = 0;

	// Command Parsing
	if (buffer[0] == '\0') {
		print_line_error("Empty string!\n");
		return -1;
	}

	// User is trying to send a message to the selected view
	if (user_input && buffer[0] != '\\') {
		int i = 0;
		while (buffer[i] != '\n' && i < len) { // eat until end or NL
			i++;
		}

		if (buffer[i] != '\n') {
			panic("You screwed up, sonny! %.*s\n", buffer, len);
		}

		if (i != 0) {
			if (client->view_type == VIEW_INTERNAL) {
				print_line_error("Please select an external view!\n");
				return -1;
			}

			*toks_len = 1;
		}

		toks[0].ptr = buffer;
		toks[0].size = i;
		return i;
	}

	int toks_found = 0;
	bool started_token = false;
	bool started_terminator = false;
	int i = 0;
	for (;;) {
		while (buffer[i] == ' ' && i < len) { // eat until not spaces
			i++;
		}

		if (buffer[i] == '\n') { // Handle no args and token ending with NULL cases
			if (started_token) {
				toks[toks_found].size = buffer + i - toks[toks_found].ptr;
				toks_found++;
				break;
			}

			i++;
			break;
		}

		if (i >= len) {
			break;
		}

		started_token = true;
		toks[toks_found].ptr = buffer + i;

		if ((i + 1) < len && buffer[i] == '\\' && buffer[i + 1] == ':') { // Allow ':' escaping
			toks[toks_found].ptr++;
			i++;
		} else if (buffer[i] == ':') { // Must start the token with the terminator to trigger this
			started_terminator = true;

			toks[toks_found].ptr++;
			i++;
		}

		while (buffer[i] != '\n' && buffer[i] != '\0' && i < len) { // consume until token finish

			// Once : is hit, stop using whitespace as a delim
			if (!started_terminator && buffer[i] == ' ') {
				break;
			}

			i++;
		}
		if (i >= len) {
			break;
		}

		toks[toks_found].size = buffer + i - toks[toks_found].ptr;
		toks_found++;
		started_token = false;

		if (toks_found > MAX_TOKS) {
			print_line_error("Got too many tokens! got %d\n", toks_found);
			return i;
		}
	}

	// If we got a :\n from the server, don't bother passing that along as a token
	if (toks[toks_found - 1].size == 0) {
		toks[toks_found - 1].ptr = NULL;
		toks_found--;
	}

	*toks_len = toks_found;
	clear_off = i;

/*
	for (int i = 0; i < toks_found; i++) {
		print_line_internal("%d: [size: %d, {%.*s}]\n", i, toks[i].size, toks[i].size, toks[i].ptr);
	}
*/

	if (!toks_found) {
		print_line_error("No tokens?\n");
	}

	return clear_off;
}

int add_to_usermap(client_state_t *client, token_t *user) {
	char username[MAX_REFNAME + 1] = {0};
	memcpy(username, user->ptr, user->size);

	for (int i = 0; i < client->users_len; i++) {
		if (!strcmp(client->users[i].name, username)) {
			return i;
		}
	}

	if ((client->users_len + 1) > client->max_users) {
		panic("Usermap is full!\n");
	}

	client->users[client->users_len].has_pmd = false;
	client->users[client->users_len].unread_count = 0;
	memcpy(client->users[client->users_len].name, user->ptr, user->size);

	return client->users_len++;
}

int get_user_from_map(client_state_t *client, token_t *user) {
	char username[MAX_REFNAME + 1] = {0};
	memcpy(username, user->ptr, user->size);

	for (int i = 0; i < client->users_len; i++) {
		if (!strcmp(client->users[i].name, username)) {
			return i;
		}
	}

	return -1;
}

void flush_channel_users(channel_history_t *hist) {
	memset(hist->users, 0, sizeof(int) * MAX_CHANNEL_USERS);
	hist->users_len = 0;
}

void add_user_to_channel(channel_history_t *hist, int user_id) {
	if (hist->users_len > MAX_CHANNEL_USERS) {
		panic("Too many users in channel!\n");
	}

	hist->users[hist->users_len++] = user_id;
}

int remove_user_from_channel(channel_history_t *hist, int user_id) {
	if (hist->users_len == 0) {
		// Channel is empty?
		return -1;
	}

	int i = 0;
	for (; i < hist->users_len; i++) {
		if (hist->users[i] == user_id) {
			break;
		}
	}
	if (i == hist->users_len) {
		// User not found.
		return -1;
	}

	if (i == hist->users_len - 1) {
		hist->users[i] = 0;
		hist->users_len--;
		return 0;
	}

	int tail = hist->users[hist->users_len - 1];
	hist->users[i] = tail;
	hist->users[hist->users_len - 1] = 0;
	hist->users_len--;

	return 0;
}

int get_channel_from_map(client_state_t *client, token_t *channel) {
	char channelname[MAX_REFNAME + 1] = {0};
	memcpy(channelname, channel->ptr, channel->size);

	for (int i = 0; i < client->channels_len; i++) {
		if (!strcmp(client->channel_hist[i].name, channelname)) {
			return i;
		}
	}

	return -1;
}

int add_to_channelmap(client_state_t *client, token_t *channel) {
	int channel_hist_id = get_channel_from_map(client, channel);
	if (channel_hist_id != -1) {
		return channel_hist_id;
	}

	if ((client->channels_len + 1) > client->max_channels) {
		print_line_error("Channel history is full!\n");
		return -1;
	}

	memcpy(client->channel_hist[client->channels_len++].name, channel->ptr, channel->size);
	return client->channels_len - 1;
}


void add_to_channel_history(client_state_t *client, token_t *channel, message_t *msg) {
	int channel_hist_id = add_to_channelmap(client, channel);
	channel_history_t *channel_hist = &client->channel_hist[channel_hist_id];

	// if there's nothing in the list, or if the last thing is older than the new thing, stick it at the end
	if (channel_hist->msgs_len == 0 || channel_hist->messages[channel_hist->msgs_len - 1].msg.sent < msg->created) {
		micro_msg_t *mi_msg = &channel_hist->messages[channel_hist->msgs_len].msg;
		memcpy(mi_msg->data, msg->data, msg->len);
		mi_msg->len = msg->len;
		mi_msg->sent = msg->created;
		mi_msg->id = msg->id;

		token_t sender;
		sender.ptr = msg->sender;
		sender.size = strlen(msg->sender);
		channel_hist->messages[channel_hist->msgs_len].sender_id = add_to_usermap(client, &sender);

		channel_hist->msgs_len++;
		return;
	}

	// Otherwise, figure out where it needs to go in the oldest -> newest sorted list
	int i = 0;
	for (; i < channel_hist->msgs_len; i++) {
		channel_msg_t *cur_record = &channel_hist->messages[i];
		if (cur_record->msg.id == msg->id) {
			// Message is already in the list!
			return;
		}

		if (cur_record->msg.sent > msg->created) {
			break;
		}
	}

	size_t rem_size = channel_hist->msgs_len - i;
	memmove(&channel_hist->messages[i + 1], &channel_hist->messages[i], sizeof(channel_msg_t) * rem_size);
	micro_msg_t *mi_msg = &channel_hist->messages[i].msg;
	memcpy(mi_msg->data, msg->data, msg->len);
	mi_msg->len = msg->len;
	mi_msg->sent = msg->created;
	mi_msg->id = msg->id;

	token_t sender;
	sender.ptr = msg->sender;
	sender.size = strlen(msg->sender);
	channel_hist->messages[i].sender_id = add_to_usermap(client, &sender);

	channel_hist->msgs_len++;
}

void print_channel_history(client_state_t *client, token_t *channel) {
	channel_history_t *channel_hist = NULL;
	int channel_hist_id = get_channel_from_map(client, channel);
	if (channel_hist_id != -1) {
		channel_hist = &client->channel_hist[channel_hist_id];
	}

	if (!channel_hist) {
		print_line_error("No channel found!\n");
		return;
	}

	for (int i = 0; i < channel_hist->msgs_len; i++) {
		channel_msg_t *msg = &channel_hist->messages[i];
		print_line_time(msg->msg.sent, "%s %.*s\n", client->users[msg->sender_id].name, msg->msg.len, msg->msg.data);
	}
}

int get_pm_from_map(client_state_t *client, token_t *other_user) {
	int other_id = get_user_from_map(client, other_user);
	if (other_id != -1) {
		for (int i = 0; i < client->pms_len; i++) {
			if (client->private_hist[i].other_id == other_id) {
				return i;
			}
		}
	}

	return -1;
}

int add_to_pmmap(client_state_t *client, token_t *other_user) {
	int pm_hist_id = get_pm_from_map(client, other_user);
	if (pm_hist_id != -1) {
		return pm_hist_id;
	}

	if ((client->pms_len + 1) > client->max_pms) {
		panic("PM history is full!\n");
	}

	int other_id = get_user_from_map(client, other_user);
	if (other_id == -1) {
		other_id = add_to_usermap(client, other_user);
	}

	client->private_hist[client->pms_len++].other_id = other_id;
	return client->pms_len - 1;
}

void add_to_pm_history(client_state_t *client, token_t *other_user, bool am_sender, message_t *msg) {
	int pm_hist_id = add_to_pmmap(client, other_user);
	pm_history_t *pm_hist = &client->private_hist[pm_hist_id];

	// if there's nothing in the list, or if the last thing is older than the new thing, stick it at the end
	if (pm_hist->msgs_len == 0 || pm_hist->messages[pm_hist->msgs_len - 1].msg.sent < msg->created) {
		micro_msg_t *mi_msg = &pm_hist->messages[pm_hist->msgs_len].msg;
		memcpy(mi_msg->data, msg->data, msg->len);
		mi_msg->len = msg->len;
		mi_msg->sent = msg->created;
		mi_msg->id = msg->id;
		pm_hist->messages[pm_hist->msgs_len].am_sender = am_sender;
		pm_hist->msgs_len++;

		return;
	}

	// Otherwise, figure out where it needs to go in the oldest -> newest sorted list
	int i = 0;
	for (; i < pm_hist->msgs_len; i++) {
		private_msg_t *cur_record = &pm_hist->messages[i];
		if (cur_record->msg.id == msg->id) {
			// Message is already in the list!
			return;
		}

		if (cur_record->msg.sent > msg->created) {
			break;
		}
	}

	size_t rem_size = pm_hist->msgs_len - i;
	memmove(&pm_hist->messages[i + 1], &pm_hist->messages[i], sizeof(private_msg_t) * rem_size);
	micro_msg_t *mi_msg = &pm_hist->messages[i].msg;
	memcpy(mi_msg->data, msg->data, msg->len);
	mi_msg->len = msg->len;
	mi_msg->sent = msg->created;
	mi_msg->id = msg->id;
	pm_hist->messages[i].am_sender = am_sender;

	pm_hist->msgs_len++;
}

void print_pm_history(client_state_t *client, token_t *other_user) {
	pm_history_t *pm_hist = NULL;

	int pm_hist_id = get_pm_from_map(client, other_user);
	if (pm_hist_id != -1) {
		pm_hist = &client->private_hist[pm_hist_id];
	}
	if (!pm_hist) {
		print_line_error("No pms found for that user\n");
		return;
	}

	for (int i = 0; i < pm_hist->msgs_len; i++) {
		private_msg_t *msg = &pm_hist->messages[i];
		if (msg->am_sender) {
			print_line_time(msg->msg.sent, "%s %.*s\n", client->name, msg->msg.len, msg->msg.data);
		} else {
			print_line_time(msg->msg.sent, "%.*s %.*s\n", other_user->size, other_user->ptr, msg->msg.len, msg->msg.data);
		}
	}
}

void print_msghistory(client_state_t *client, token_t *target) {
	if (target->ptr[0] == '#') {
		print_channel_history(client, target);
	} else {
		print_pm_history(client, target);
	}
}

int setup_conn(client_state_t *client, char *ip_addr_str, uint16_t port) {
	struct addrinfo hints = {0};
	struct addrinfo *res = NULL;



	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	struct in6_addr serveraddr;
	int ret = inet_pton(AF_INET, ip_addr_str, &serveraddr);
	if (ret == 1) {
		hints.ai_family = AF_INET;
		hints.ai_flags |= AI_NUMERICHOST;
	} else {
		ret = inet_pton(AF_INET6, ip_addr_str, &serveraddr);
		if (ret == 1) {
			hints.ai_family = AF_INET6;
			hints.ai_flags |= AI_NUMERICHOST;
		} else {
			print_line_internal("Unable to parse server name\n");
			return -1;
		}
	}

	char port_str[8] = {0};
	sprintf(port_str, "%u", port);

	ret = getaddrinfo(ip_addr_str, port_str, &hints, &res);
	if (ret) {
		if (ret == EAI_SYSTEM) {
			pdump("getaddrinfo failed\n");
		} else {
			print_line_internal("server not found\n");
			return -1;
		}
	}

	int sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sd < 0) {
		pdump("socket failed");
	}

	ret = connect(sd, res->ai_addr, res->ai_addrlen);
	if (ret < 0) {
		close(sd);
		print_line_internal("connect failed\n");
		return -1;
	}

	if (fcntl(sd, F_SETFL, fcntl(sd, F_GETFL) | O_NONBLOCK) < 0) {
		pdump("failed to set socket nonblocking");
	}

	client->conn.sd = sd;

	sprintf(client->ip_addr, "%s", ip_addr_str);
	client->port = port;

	client->conn.rbio = BIO_new(BIO_s_mem());
	client->conn.wbio = BIO_new(BIO_s_mem());
	client->conn.ssl = SSL_new(client->ctx);

	SSL_set_connect_state(client->conn.ssl);
	SSL_set_bio(client->conn.ssl, client->conn.rbio, client->conn.wbio);

	do_ssl_handshake(&client->conn);

	print_line_internal("Connected to %s:%u\n", client->ip_addr, client->port);
	return 0;
}

void close_conn(client_state_t *client) {
	if (client->conn.sd == -1) {
		return;
	}

	SSL_free(client->conn.ssl);
	free(client->conn.write_buf);
	free(client->conn.encrypt_buf);
	close(client->conn.sd);

	client->conn.ssl = NULL;
	client->conn.rbio = NULL;
	client->conn.wbio = NULL;
	client->conn.write_buf = NULL;
	client->conn.encrypt_buf = NULL;
	client->conn.sd = -1;
	client->conn.id = -1;
	client->verified_server_cert = false;

	memset(client->conn.addr, 0, MAX_USER_ADDR);
	memset(client->conn.name, 0, MAX_REFNAME);
}

// Man, this is ugly, but not as ugly as maintaining multiple lists
#define INTERNAL_COMMANDS \
	xtype(SWITCHTO), \
	xtype(CONNECT), \
	xtype(DISCONNECT), \
	xtype(MSG), \
	xtype(HELP), \
	xtype(QUIT)

#define xtype(name) INT_CMD_##name

typedef enum {
	INTERNAL_COMMANDS,
	INT_CMD_ERROR,
	INT_CMD_PASS
} internal_cmd_t;

#undef xtype

#define xtype(name) #name
char *internal_cmd_strs[] = { INTERNAL_COMMANDS };
int internal_cmd_str_len = sizeof(internal_cmd_strs) / sizeof(char *);

char *external_cmd_strs[] = { UNAUTH_COMMANDS, NORMAL_COMMANDS, ADMIN_COMMANDS };
int external_cmd_str_len = sizeof(external_cmd_strs) / sizeof(char *);

internal_cmd_t dispatch_internal_commands(client_state_t *client, token_t *toks, int toks_len) {
	conn_t *conn = &client->conn;

	internal_cmd_t command_type = INT_CMD_PASS;

	if (toks_len == 1 && toks[0].ptr[0] != '\\') {

		char *target;
		if (client->view_type == VIEW_CHANNEL) {
			target = client->channel_hist[client->view_id].name;
		} else if (client->view_type == VIEW_PM) {
			target = client->users[client->private_hist[client->view_id].other_id].name;
		} else {
			panic("How am I here?\n");
		}

		char tmp[MAX_MESSAGE_LEN + 1] = {0};
		int sz = sprintf(tmp, "\\msg %s :%.*s\n", target, toks[0].size, toks[0].ptr);
		send_to_conn(client, tmp, sz);

		return INT_CMD_MSG;
	}

	// Chop \ off of command, and build args list
	char command[MAX_COMMAND + 1] = {0};
	if ((toks[0].size - 1) > MAX_COMMAND) {
		print_line_error("command is too long!\n");
		return INT_CMD_ERROR;
	}
	memcpy(command, toks[0].ptr + 1, toks[0].size - 1);


	int i = 0;
	for (; i < internal_cmd_str_len; i++) {
		if (!strcasecmp(internal_cmd_strs[i], command)) {
			command_type = i;
			break;
		}
	}

	token_t args[MAX_TOKS] = {0};
	for (int i = 1; i < toks_len; i++) {
		args[i - 1] = toks[i];
	}

	int args_found = toks_len - 1;

	switch (command_type) {
		case INT_CMD_SWITCHTO: {
			if (args_found != 1) {
				print_line_error("please specify a channel / pm to switch to\n");
				return INT_CMD_ERROR;
			}

			if (args[0].ptr[0] == '*') {
				if (client->view_id == 0 && client->view_type == VIEW_INTERNAL) {
					break;
				}

				client->view_id = 0;
				client->view_type = VIEW_INTERNAL;

				redraw = true;
			} else if (args[0].ptr[0] == '#') {
				int channel_hist_id = get_channel_from_map(client, &args[0]);
				if (channel_hist_id == -1) {
					print_line_error("Channel not found! Try running \\channels first \n");
					return INT_CMD_ERROR;
				}

				if (client->view_id == channel_hist_id && client->view_type == VIEW_CHANNEL) {
					break;
				}

				if (client->view_type != VIEW_CHANNEL) {
					redraw = true;
				}

				print_line_internal("Switching to %.*s\n", args[0].size, args[0].ptr);
				flush_scrollback(page_scrollback_buffer, &page_scrollback_len);
				print_channel_history(client, &args[0]);
				client->view_id = channel_hist_id;
				client->view_type = VIEW_CHANNEL;

				// Plz mr.server, can has history?
				char tmp1[MAX_MESSAGE_LEN] = {0};
				int n = sprintf(tmp1, "\\history %.*s\n", args[0].size, args[0].ptr);
				send_to_conn(client, tmp1, n);

				char tmp2[MAX_MESSAGE_LEN] = {0};
				n = sprintf(tmp2, "\\channelusers %.*s\n", args[0].size, args[0].ptr);
				send_to_conn(client, tmp2, n);

				char tmp3[MAX_MESSAGE_LEN] = {0};
				n = sprintf(tmp3, "\\markread %.*s\n", args[0].size, args[0].ptr);
				send_to_conn(client, tmp3, n);
			} else {
				int pm_hist_id = get_pm_from_map(client, &args[0]);
				if (pm_hist_id == -1) {
					print_line_error("No PMs found with that user \\users first \n");
					return INT_CMD_ERROR;
				}

				if (client->view_id == pm_hist_id && client->view_type == VIEW_PM) {
					break;
				}

				if (client->view_type != VIEW_PM) {
					redraw = true;
				}

				print_line_internal("Switching to %.*s\n", args[0].size, args[0].ptr);
				flush_scrollback(page_scrollback_buffer, &page_scrollback_len);
				print_pm_history(client, &args[0]);
				client->view_id = pm_hist_id;
				client->view_type = VIEW_PM;

				// Plz mr.server, can has history?
				char tmp[MAX_MESSAGE_LEN] = {0};
				int n = sprintf(tmp, "\\history %.*s\n", args[0].size, args[0].ptr);
				send_to_conn(client, tmp, n);

				char tmp3[MAX_MESSAGE_LEN] = {0};
				n = sprintf(tmp3, "\\markread %.*s\n", args[0].size, args[0].ptr);
				send_to_conn(client, tmp3, n);
			}
		} break;
		case INT_CMD_HELP: {
			if (client->conn.sd != -1) {
				char *unauth_cmd_strs[] = { UNAUTH_COMMANDS };
				char *normal_cmd_strs[] = { NORMAL_COMMANDS };
				char *admin_cmd_strs[] = { ADMIN_COMMANDS };

				int unauth_cmd_str_len = sizeof(unauth_cmd_strs) / sizeof(char *);
				int normal_cmd_str_len = sizeof(normal_cmd_strs) / sizeof(char *);
				int admin_cmd_str_len = sizeof(admin_cmd_strs) / sizeof(char *);

				print_line_internal("server command list:\n");
				print_line_internal("unauthed:\n");
				for (int i = 0; i < unauth_cmd_str_len; i++) {
					print_line_internal("- %s\n", unauth_cmd_strs[i]);
				}

				print_line_internal("authed:\n");
				for (int i = 0; i < normal_cmd_str_len; i++) {
					print_line_internal("- %s\n", normal_cmd_strs[i]);
				}

				print_line_internal("admin:\n");
				for (int i = 0; i < admin_cmd_str_len; i++) {
					print_line_internal("- %s\n", admin_cmd_strs[i]);
				}
			}

			print_line_internal("local command list:\n");
			for (int i = 0; i < internal_cmd_str_len; i++) {
				print_line_internal("- %s\n", internal_cmd_strs[i]);
			}

		} break;
		case INT_CMD_DISCONNECT: {
			if (args_found != 0) {
				print_line_error("Disconnect takes no args\n");
				return INT_CMD_ERROR;
			}

			if (client->conn.sd == -1) {
				print_line_error("Client already disconnected!\n");
				return INT_CMD_ERROR;
			}

			close_conn(client);
			print_line_internal("connection closed!\n");
		} break;
		case INT_CMD_CONNECT: {
			if (args_found != 2) {
				print_line_error("should have 2 args, <ip_addr> <port> %d\n", args_found);
				return INT_CMD_ERROR;
			}


			if (client->conn.sd != -1) {
				print_line_error("Client already connected!\n");
				return INT_CMD_ERROR;
			}

			if (args[0].size > INET6_ADDRSTRLEN) {
				print_line_error("IP address invalid! %.*s\n", args[0].size, args[0].ptr);
				return INT_CMD_ERROR;
			}

			if (args[1].size > MAX_PORT_LEN) {
				print_line_error("port invalid! %.*s\n", args[1].size, args[1].ptr);
				return INT_CMD_ERROR;
			}

			char ip_addr[INET6_ADDRSTRLEN] = {0};
			char port_str[MAX_PORT_LEN + 1] = {0};
			memcpy(ip_addr, args[0].ptr, args[0].size);
			memcpy(port_str, args[1].ptr, args[1].size);

			char *stupid_ptr = NULL;
			size_t port = strtol(port_str, &stupid_ptr, 10);
			if (!port && port_str == stupid_ptr) {
				print_line_error("Invalid port! %s\n", port_str);
				return INT_CMD_ERROR;
			}

			memcpy(client->ip_addr, ip_addr, args[0].size);
			client->ip_addr[args[0].size] = 0;
			client->port = port;
			client->has_ip = true;

			retry_count = 0;
		} break;
		case INT_CMD_QUIT: {
			root_killme = true;
		} break;
		default: {
			if (client->conn.sd == -1) {
				print_line_error("Client is disconnected!\n");
				return INT_CMD_ERROR;
			}

			return INT_CMD_PASS;
		}
	}

	return command_type;
}

void dispatch_inbound_commands(client_state_t *client, token_t *toks, int toks_len) {
	conn_t *conn = &client->conn;

	// Handle it if the server asks US for something
	if (toks[0].ptr[0] == '\\') {
		char command[MAX_COMMAND + 1] = {0};
		memcpy(command, toks[0].ptr, toks[0].size);

		if (!strcmp(command, "\\toss")) {
			char yeet_buf[] = "\\yeet\n";
			send_to_conn(client, yeet_buf, sizeof(yeet_buf) - 1);
			return;
		} else {
			print_line_error("Unhandled server command! %.*s\n", toks[0].size, toks[0].ptr);
			return;
		}
	}

	if (toks_len < 4) {
		panic("Weird message?\n");
	}

	// Response format: status time [from] command args
	typedef enum {
		STATUS_IDX = 0,
		TIME_IDX,
		FROM_IDX,
		COMMAND_IDX,
	} response_idx_t;

	#define ERRCODE_LEN 20
	char errorcode_str[ERRCODE_LEN + 1] = {0};
	if (toks[STATUS_IDX].size > ERRCODE_LEN) {
		panic("Invalid errorcode? %.*s\n", toks[STATUS_IDX].size, toks[STATUS_IDX].ptr);
	}
	memcpy(errorcode_str, toks[STATUS_IDX].ptr, toks[STATUS_IDX].size);

	char *stupid_ptr = NULL;
	size_t errorcode = strtol(errorcode_str, &stupid_ptr, 10);
	if (!errorcode && errorcode_str == stupid_ptr) {
		panic("Invalid number! %s\n", errorcode_str);
	}

	#define TIMECODE_LEN 20
	char timecode_str[TIMECODE_LEN + 1] = {0};
	if (toks[TIME_IDX].size > TIMECODE_LEN) {
		panic("Invalid timecode? %.*s\n", toks[TIME_IDX].size, toks[TIME_IDX].ptr);
	}
	memcpy(timecode_str, toks[TIME_IDX].ptr, toks[TIME_IDX].size);

	stupid_ptr = NULL;
	size_t msg_time = strtol(timecode_str, &stupid_ptr, 10);
	if (!msg_time && timecode_str == stupid_ptr) {
		panic("Invalid number! %s\n", timecode_str);
	}

	// Inform the user if things are borked
	if (errorcode) {
		print_line_error("%s\n", toks[FROM_IDX + 1].ptr);
		return;
	}

	// Ignore things deemed garbage
	if (!(toks_len > 3 && toks[COMMAND_IDX].ptr[0] == '\\')) {
		return;
	}

	char command[MAX_COMMAND + 1] = {0};
	memcpy(command, toks[COMMAND_IDX].ptr + 1, toks[COMMAND_IDX].size - 1); // Chop off \

	cmd_t cmd = CMD_ERROR;
	int i = 0;
	for (; i < external_cmd_str_len; i++) {
		if (!strcasecmp(external_cmd_strs[i], command)) {
			cmd = i;
			break;
		}
	}

	switch (cmd) {
		case CMD_LIVE: {
			token_t from_tok = toks[FROM_IDX];
			int user_id = add_to_usermap(client, &from_tok);
			client->users[user_id].is_live = true;
			redraw = true;
			return;
		} break;
		case CMD_LOGIN: {
			token_t msg_tok = toks[COMMAND_IDX + 1];
			memcpy(client->auth_token, msg_tok.ptr, msg_tok.size);

			token_t sender_tok = toks[FROM_IDX];
			memset(client->name, 0, MAX_REFNAME);
			memcpy(client->name, sender_tok.ptr, sender_tok.size);

			client->user_id = add_to_usermap(client, &sender_tok);
			print_line_internal("Login Successful\n");

			char *init_lines[] = {
				"\\channels\n",
				"\\mychannels\n",
				"\\users\n",
				"\\mypms\n",
				"\\livecheck\n"
			};
			token_t init_toks[5];
			for (int i = 0; i < 5; i++) {
				init_toks[i].ptr = init_lines[i];
				init_toks[i].size = strlen(init_lines[i]);
			}

			batch_to_conn(client, init_toks, 5);
			return;
		} break;
		case CMD_REGISTER: {
			token_t msg_tok = toks[COMMAND_IDX + 1];
			memcpy(client->auth_token, msg_tok.ptr, msg_tok.size);

			token_t sender_tok = toks[FROM_IDX];
			memset(client->name, 0, MAX_REFNAME);
			memcpy(client->name, sender_tok.ptr, sender_tok.size);

			client->user_id = add_to_usermap(client, &sender_tok);
			print_line_internal("Registration Successful\n");

			char *init_lines[] = {
				"\\channels\n",
				"\\mychannels\n",
				"\\users\n",
				"\\mypms\n",
				"\\livecheck\n"
			};

			token_t init_toks[5];
			for (int i = 0; i < 5; i++) {
				init_toks[i].ptr = init_lines[i];
				init_toks[i].size = strlen(init_lines[i]);
			}

			batch_to_conn(client, init_toks, 5);
			return;
		} break;
		case CMD_LIVECHECK: {
			token_t msg_tok = toks[COMMAND_IDX + 1];
			print_line_internal("Live users: %.*s\n", msg_tok.size, msg_tok.ptr);

			for (int i = 0; i < client->users_len; i++) {
				client->users[i].is_live = false;
			}

			redraw = true;

			if (!msg_tok.size) {
				// Got no other live users, just ret early
				return;
			}

			char *users_str = msg_tok.ptr;
			int i = 0;
			for (;;) {
				while ((users_str[i] == ' ' || users_str[i] == ',') && i < msg_tok.size) {
					i++;
				}

				token_t user;
				user.ptr = users_str + i;

				while (users_str[i] != '\n' && users_str[i] != '\0' && i < msg_tok.size) {
					if (users_str[i] == ' ' || users_str[i] == ',') {
						break;
					}

					i++;
				}

				user.size = users_str + i - user.ptr;

				int user_id = add_to_usermap(client, &user);
				client->users[user_id].is_live = true;

				if (i >= msg_tok.size) {
					break;
				}
			}
		} break;
		case CMD_MSG: {
			if (toks_len != 7) {
				goto unhandled_cmd;
			}

			token_t msg_id_tok = toks[COMMAND_IDX + 1];
			token_t sender_tok = toks[FROM_IDX];
			token_t target_tok = toks[COMMAND_IDX + 2];
			token_t msg_tok = toks[COMMAND_IDX + 3];

			#define MSG_ID_LEN 20
			char msg_id_str[MSG_ID_LEN + 1] = {0};
			if (msg_id_tok.size > MSG_ID_LEN) {
				panic("Invalid message id? %.*s\n", msg_id_tok.size, msg_id_tok.ptr);
			}
			memcpy(msg_id_str, msg_id_tok.ptr, msg_id_tok.size);

			stupid_ptr = NULL;
			size_t ret_flag = strtol(msg_id_str, &stupid_ptr, 10);
			if (!ret_flag && msg_id_str == stupid_ptr) {
				panic("Invalid number! %s\n", msg_id_str);
			}
			uint64_t msg_id = ret_flag;

			message_t msg = {0};
			msg.id = msg_id;
			msg.created = msg_time;
			msg.len = msg_tok.size;
			memcpy(msg.data,   msg_tok.ptr,    msg_tok.size);
			memcpy(msg.target, target_tok.ptr, target_tok.size);
			memcpy(msg.sender, sender_tok.ptr, sender_tok.size);

			if (msg.target[0] == '#') {
				add_to_channel_history(client, &target_tok, &msg);
				int channel_hist_id = get_channel_from_map(client, &target_tok);

				if (client->view_type == VIEW_CHANNEL && client->view_id == channel_hist_id) {
					flush_scrollback(page_scrollback_buffer, &page_scrollback_len);
					print_channel_history(client, &target_tok);
				} else {
					client->channel_hist[channel_hist_id].unread_count += 1;
					redraw = true;
				}
			} else {
				token_t other_user;
				bool am_sender;

				if (!strcmp(client->name, msg.target)) {
					other_user = sender_tok;
					am_sender = false;
				} else if (!strcmp(client->name, msg.sender)) {
					other_user = target_tok;
					am_sender = true;
				} else {
					panic("??? %s != %s != %s ???\n", client->name, msg.target, msg.sender);
				}

				add_to_pm_history(client, &other_user, am_sender, &msg);
				int pm_hist_id = get_pm_from_map(client, &other_user);
				client->users[client->private_hist[pm_hist_id].other_id].has_pmd = true;

				if (client->view_type == VIEW_PM && client->view_id == pm_hist_id) {
					flush_scrollback(page_scrollback_buffer, &page_scrollback_len);
					print_pm_history(client, &other_user);
				} else {
					client->users[client->private_hist[pm_hist_id].other_id].unread_count += 1;
					redraw = true;
				}
			}

			return;
		} break;
		case CMD_COUNTUNREAD: {
			token_t msg_tok = toks[COMMAND_IDX + 2];
			print_line_internal("%.*s\n", msg_tok.size, msg_tok.ptr);
		} break;
		case CMD_MARKREAD: {
			token_t target_tok = toks[COMMAND_IDX + 1];
			if (target_tok.size == 0) {
				panic("borked markread!\n");
			}

			if (target_tok.ptr[0] == '#') {
				int channel_hist_id = get_channel_from_map(client, &target_tok);
				client->channel_hist[channel_hist_id].unread_count = 0;
			} else {
				int pm_hist_id = get_pm_from_map(client, &target_tok);
				if (pm_hist_id == -1) {
					panic("borked pm map?\n");
				}
				client->users[client->private_hist[pm_hist_id].other_id].unread_count = 0;
			}

			redraw = true;
		} break;
		case CMD_CHANNELUSERS: {
			if (toks_len == 5) {
				print_line_internal("Channel has no users\n");
				return;
			}

			token_t channel_tok = toks[COMMAND_IDX + 1];
			token_t msg_tok = toks[COMMAND_IDX + 2];

			int channel_hist_id = get_channel_from_map(client, &channel_tok);
			flush_channel_users(&client->channel_hist[channel_hist_id]);

			char *users_str = msg_tok.ptr;
			int i = 0;
			for (;;) {
				while ((users_str[i] == ' ' || users_str[i] == ',') && i < msg_tok.size) {
					i++;
				}

				token_t user;
				user.ptr = users_str + i;

				while (users_str[i] != '\n' && users_str[i] != '\0' && i < msg_tok.size) {
					if (users_str[i] == ' ' || users_str[i] == ',') {
						break;
					}

					i++;
				}

				user.size = users_str + i - user.ptr;

				int user_id = add_to_usermap(client, &user);
				add_user_to_channel(&client->channel_hist[channel_hist_id], user_id);

				if (i >= msg_tok.size) {
					break;
				}
			}

			print_line_internal("%.*s -- %.*s\n", channel_tok.size, channel_tok.ptr, msg_tok.size, msg_tok.ptr);
			redraw = true;
			return;
		} break;
		case CMD_USERS: {
			token_t msg_tok = toks[COMMAND_IDX + 1];

			print_line_internal("%.*s\n", msg_tok.size, msg_tok.ptr);

			char *users_str = msg_tok.ptr;
			int i = 0;
			for (;;) {
				while ((users_str[i] == ' ' || users_str[i] == ',') && i < msg_tok.size) {
					i++;
				}

				token_t user;
				user.ptr = users_str + i;

				while (users_str[i] != '\n' && users_str[i] != '\0' && i < msg_tok.size) {
					if (users_str[i] == ' ' || users_str[i] == ',') {
						break;
					}

					i++;
				}

				user.size = users_str + i - user.ptr;

				// Only add users if not me
				int user_id = add_to_usermap(client, &user);
				if (client->user_id != user_id) {
					int ret = add_to_pmmap(client, &user);
					print_line_internal("added %.*s to map\n", user.size, user.ptr);
				}

				if (i >= msg_tok.size) {
					break;
				}
			}

			return;
		} break;
		case CMD_JOIN: {
			token_t channel_tok = toks[COMMAND_IDX + 1];
			token_t sender_tok = toks[FROM_IDX];
			print_line_internal("%.*s joined %.*s\n", sender_tok.size, sender_tok.ptr, channel_tok.size, channel_tok.ptr);

			int user_id = add_to_usermap(client, &sender_tok);
			int channel_hist_id = add_to_channelmap(client, &channel_tok);
			if (channel_hist_id == -1) {
				panic("Invalid channel hist?\n");
			}

			add_user_to_channel(&client->channel_hist[channel_hist_id], user_id);

			if (client->user_id == user_id) {
				client->channel_hist[channel_hist_id].joined = true;
			}
			return;
		} break;
		case CMD_LEAVE: {
			token_t channel_tok = toks[COMMAND_IDX + 1];
			token_t sender_tok = toks[FROM_IDX];
			print_line_internal("%.*s left %.*s\n", sender_tok.size, sender_tok.ptr, channel_tok.size, channel_tok.ptr);

			int user_id = add_to_usermap(client, &sender_tok);
			int channel_hist_id = add_to_channelmap(client, &channel_tok);
			if (channel_hist_id == -1) {
				panic("Invalid channel hist?\n");
			}

			remove_user_from_channel(&client->channel_hist[channel_hist_id], user_id);

			if (client->user_id == user_id) {
				client->channel_hist[channel_hist_id].joined = false;
			}
			return;
		} break;
		case CMD_TIME: {
			token_t msg_tok = toks[COMMAND_IDX + 1];
			print_line_internal("%.*s\n", msg_tok.size, msg_tok.ptr);
			return;
		} break;
		case CMD_CHANNELS: {
			token_t msg_tok = toks[COMMAND_IDX + 1];
			print_line_internal("%.*s\n", msg_tok.size, msg_tok.ptr);

			char *channels_str = msg_tok.ptr;
			int i = 0;
			for (;;) {
				while ((channels_str[i] == ' ' || channels_str[i] == ',') && i < msg_tok.size) {
					i++;
				}

				token_t channel;
				channel.ptr = channels_str + i;

				while (channels_str[i] != '\n' && channels_str[i] != '\0' && i < msg_tok.size) {
					if (channels_str[i] == ' ' || channels_str[i] == ',') {
						break;
					}

					i++;
				}

				channel.size = channels_str + i - channel.ptr;

				int ret = add_to_channelmap(client, &channel);
				if (ret != -1) {
					print_line_internal("added %.*s to map\n", channel.size, channel.ptr);
				}

				if (i >= msg_tok.size) {
					break;
				}
			}

			return;
		} break;
		case CMD_MYCHANNELS: {
			if (toks_len == 4) {
				print_line_internal("You have no joined channels\n");
				return;
			}

			token_t msg_tok = toks[COMMAND_IDX + 1];
			print_line_internal("%.*s\n", msg_tok.size, msg_tok.ptr);

			char *channels_str = msg_tok.ptr;
			int i = 0;
			for (;;) {
				// Gimme the first tuple
				while (channels_str[i] == ' ' && i < msg_tok.size) {
					i++;
				}
				if (channels_str[i] != '(') {
					print_line_internal("Invalid channels ret\n");
					return;
				}
				if ((i + 1) >= msg_tok.size) panic("bad channels!\n");
				i++;

				token_t channel;
				channel.ptr = channels_str + i;

				// accumulate thingies until we hit the comma
				while (channels_str[i] != ',' && i < msg_tok.size) {
					i++;
				}
				if (i >= msg_tok.size) panic("bad channels!\n");

				channel.size = channels_str + i - channel.ptr;

				// gimme element 2
				while ((channels_str[i] == ',' || channels_str[i] == ' ') && i < msg_tok.size) {
					i++;
				}
				if (i >= msg_tok.size) panic("bad channels!\n");

				char *num_start = channels_str + i;

				// accumulate more things until unread is fully consumed
				while (channels_str[i] != ')' && i < msg_tok.size) {
					i++;
				}
				if (i >= msg_tok.size) panic("bad channels!\n");

				int num_size = channels_str + i - num_start;
				i++; // get past the end )

				char *stupid_ptr = NULL;
				size_t unread_msgs = strtol(num_start, &stupid_ptr, 10);
				if (!unread_msgs && num_start == stupid_ptr) {
					panic("Invalid port! %.*s\n", num_size, num_start);
				}


				int ret = add_to_channelmap(client, &channel);
				if (ret == -1) {
					break;
				}

				client->channel_hist[ret].joined = true;
				client->channel_hist[ret].unread_count = unread_msgs;
				print_line_internal("added %.*s to map\n", channel.size, channel.ptr);

				// skip the trailing comma if necessary
				if (channels_str[i] == ',') {
					i++;
				}

				if (i >= msg_tok.size) {
					break;
				}
			}

			return;
		} break;
		case CMD_MYPMS: {
			if (toks_len == 4) {
				print_line_internal("You have no PMs\n");
				return;
			}

			token_t msg_tok = toks[COMMAND_IDX + 1];

			print_line_internal("PM list: %.*s\n", msg_tok.size, msg_tok.ptr);

			char *users_str = msg_tok.ptr;
			int i = 0;
			for (;;) {
				// Gimme the first tuple
				while (users_str[i] == ' ' && i < msg_tok.size) {
					i++;
				}
				if (users_str[i] != '(') {
					print_line_internal("Invalid pm ret\n");
					return;
				}
				if ((i + 1) >= msg_tok.size) panic("bad PMs!\n");
				i++;

				token_t user;
				user.ptr = users_str + i;

				// accumulate thingies until we hit the comma
				while (users_str[i] != ',' && i < msg_tok.size) {
					i++;
				}
				if (i >= msg_tok.size) panic("bad PMs!\n");

				user.size = users_str + i - user.ptr;

				// gimme element 2
				while ((users_str[i] == ',' || users_str[i] == ' ') && i < msg_tok.size) {
					i++;
				}
				if (i >= msg_tok.size) panic("bad PMs!\n");

				char *num_start = users_str + i;

				// accumulate more things until unread is fully consumed
				while (users_str[i] != ')' && i < msg_tok.size) {
					i++;
				}
				if (i >= msg_tok.size) panic("bad PMs!\n");

				int num_size = users_str + i - num_start;
				i++; // get past the end )

				char *stupid_ptr = NULL;
				size_t unread_msgs = strtol(num_start, &stupid_ptr, 10);
				if (!unread_msgs && num_start == stupid_ptr) {
					panic("Invalid port! %.*s\n", num_size, num_start);
				}

				// Only add users if not me
				int user_id = add_to_usermap(client, &user);
				if (client->user_id != user_id) {
					int ret = add_to_pmmap(client, &user);
					client->users[user_id].has_pmd = true;
					client->users[user_id].unread_count += unread_msgs;
					print_line_internal("added %.*s to map\n", user.size, user.ptr);
				}

				// skip the trailing comma if necessary
				if (users_str[i] == ',') {
					i++;
				}

				if (i >= msg_tok.size) {
					break;
				}
			}
			return;
		} break;
		case CMD_HISTORY: {
			token_t msg_tok = toks[COMMAND_IDX + 2];
			print_line_internal("GOT: %.*s\n", msg_tok.size, msg_tok.ptr);
			return;
		} break;
		case CMD_GENTOKEN: {
			token_t msg_tok = toks[COMMAND_IDX + 1];
			print_line_internal("%.*s\n", msg_tok.size, msg_tok.ptr);
			return;
		} break;
		default: {
unhandled_cmd:
			panic("Unhandled server update! %d: %s\n", cmd, command);
		}
	}
}

#ifndef NO_CURSES
void init_client(void) {
	initscr();
	noecho();
	cbreak();
	nodelay(stdscr, TRUE);
	keypad(stdscr, TRUE);
	nonl();
	erase();
	refresh();

	getmaxyx(stdscr, max_term_row, max_term_col);
	chat_win = newwin(max_term_row, max_term_col - MAX_REFNAME, 0, 0);
	meta_win = newwin(max_term_row, MAX_REFNAME, 0, max_term_col - MAX_REFNAME);
	wrefresh(chat_win);
	wrefresh(meta_win);

	getmaxyx(chat_win, max_chat_row, max_chat_col);
	getmaxyx(chat_win, max_meta_row, max_meta_col);

	wmove(chat_win, max_chat_row - 2, 0);
	wrefresh(chat_win);
	window_resized = true;

	if (has_colors() == FALSE) {
		panic("Get colors, scrub\n");
	}

	start_color();
	use_default_colors();
	init_pair(1, COLOR_RED, -1);
}

void draw_chat_bounds(void) {
	mvwhline(chat_win, max_chat_row - 3, 0, 0, max_chat_col);
	mvwhline(chat_win, max_chat_row - 1, 0, 0, max_chat_col);
	wmove(chat_win, max_chat_row - 2, 0);
}
void draw_meta_bounds(void) {
	mvwvline(meta_win, 0, 0, 0, max_meta_row);
}

void print_keybuf(char *buf, int len) {
	wmove(chat_win, max_chat_row - 2, 0);
	wclrtoeol(chat_win);
	wprintw(chat_win, "%.*s", len, buf);
	wmove(chat_win, max_chat_row - 2, cur_col);
}

void redraw_client(client_state_t *client, char *key_buffer, int key_len) {
	if (window_resized) {
		getmaxyx(stdscr, max_term_row, max_term_col);

		delwin(chat_win);
		delwin(meta_win);

		int meta_width = MAX_REFNAME + 4; // adds room for '*!@ ' modifiers
		chat_win = newwin(max_term_row, max_term_col - meta_width, 0, 0);
		meta_win = newwin(max_term_row, meta_width, 0, max_term_col - meta_width);

		getmaxyx(meta_win, max_meta_row, max_meta_col);
		getmaxyx(chat_win, max_chat_row, max_chat_col);


		redraw = true;
		window_resized = false;
	}

	// only update the screen if necessary
	if (!redraw) {
		return;
	}

	werase(chat_win);
	werase(meta_win);

	char **scrollback_buffer;
	int scrollback_len;
	if (client->view_type == VIEW_INTERNAL) {
		scrollback_buffer = internal_scrollback_buffer;
		scrollback_len = internal_scrollback_len;
	} else {
		scrollback_buffer = page_scrollback_buffer;
		scrollback_len = page_scrollback_len;
	}

	int print_row = max_chat_row - 3; // don't print on top of the cmdline
	for (int i = scrollback_len - 1; i >= 0; i--) {
		char *line = scrollback_buffer[i];
		char *ptr = line;

		// because doing a strlen and then a nl check is *slow*
		int nl_count = 0;
		while (*ptr) {
			if (*ptr == '\n') {
				nl_count++;
			}

			ptr++;
		}

		int line_size = ptr - line;

		line_size -= 1; // chop the null to make the wrap calc make sense

		// rounding *up* so that we display all the lines
		int num_lines = MAX((line_size + (max_chat_col - 1)) / max_chat_col, nl_count);
		print_row -= num_lines;

		if (print_row < 3) { // avoid drawing on top of the header info
			break;
		}

		mvwprintw(chat_win, 2, 0, "%d, %d, %d, %d\n", nl_count, num_lines, line_size, max_chat_col);

		mvwaddstr(chat_win, print_row, 0, scrollback_buffer[i]);
	}

	if (client->view_type == VIEW_INTERNAL) {
		mvwaddstr(chat_win, 0, 0, "view -- internal\n");
	} else if (client->view_type == VIEW_PM) {
		mvwprintw(chat_win, 0, 0, "view -- PM %s\n", client->users[client->private_hist[client->view_id].other_id].name);
	} else if (client->view_type == VIEW_CHANNEL) {
		char *channelname = client->channel_hist[client->view_id].name;
		if (client->channel_hist[client->view_id].joined) {
			mvwprintw(chat_win, 0, 0, "view -- Channel %s\n", channelname);
		} else {
			mvwprintw(chat_win, 0, 0, "view -- Channel %s -- Not Joined\n", channelname);
		}
	}

	int meta_row = 0;
	if (client->conn.sd == -1) {
		mvwprintw(meta_win, meta_row++, 1, "Disconnected");
	} else if (!strcmp(client->auth_token, "0")) {
		mvwprintw(meta_win, meta_row++, 1, "Not Logged In");
		meta_row++;
		mvwprintw(meta_win, meta_row++, 1, "Connected to:");
		mvwaddstr(meta_win, meta_row++, 1, client->ip_addr);
	} else {
		mvwprintw(meta_win, meta_row++, 1, "@ %s", client->name);

		meta_row++;

		mvwprintw(meta_win, meta_row++, 1, "All Channels");

		for (int i = 0; i < client->channels_len; i++) {
			char joined = ' ';
			char new_msgs = ' ';
			if (client->channel_hist[i].joined) {
				joined = '*';
			}

			if (client->channel_hist[i].unread_count > 0) {
				new_msgs = '!';
			}

			mvwprintw(meta_win, meta_row++, 1, "%c%c  %s", joined, new_msgs, client->channel_hist[i].name);
		}

		meta_row++; // stick a space between channel and PM lists

		if (client->view_type == VIEW_INTERNAL || client->view_type == VIEW_PM) {
			mvwprintw(meta_win, meta_row++, 1, "All Users");
			for (int i = 0; i < client->users_len; i++) {
				char has_pmd = ' ';
				char new_msgs = ' ';
				char live = ' ';

				if (client->users[i].has_pmd) {
					has_pmd = '*';
				}

				if (client->users[i].unread_count > 0) {
					new_msgs = '!';
				}

				if (client->users[i].is_live) {
					live = '@';
				}

				mvwprintw(meta_win, meta_row++, 1, "%c%c%c %s", has_pmd, new_msgs, live, client->users[i].name);
			}
		} else {
			mvwprintw(meta_win, meta_row++, 1, "Channel Users");
			for (int i = 0; i < client->channel_hist[client->view_id].users_len; i++) {
				int user_id = client->channel_hist[client->view_id].users[i];
				char has_pmd = ' ';
				char new_msgs = ' ';
				char live = ' ';

				if (client->users[user_id].has_pmd) {
					has_pmd = '*';
				}

				if (client->users[user_id].unread_count > 0) {
					new_msgs = '!';
				}

				if (client->users[user_id].is_live) {
					live = '@';
				}

				mvwprintw(meta_win, meta_row++, 1, "%c%c%c %s", has_pmd, new_msgs, live, client->users[user_id].name);
			}
		}
	}

	if (has_error) {
		wattron(chat_win, COLOR_PAIR(1));
		mvwaddstr(chat_win, 1, 0, error_buffer);
		wattroff(chat_win, COLOR_PAIR(1));
		has_error = false;
	}

	draw_meta_bounds();
	draw_chat_bounds();
	print_keybuf(key_buffer, key_len);

	wrefresh(meta_win);
	wrefresh(chat_win);

	redraw = false;
}
#else
void init_client(void) { return; }
void draw_chat_bounds(void) { return; }
void draw_meta_bounds(void) { return; }
void print_keybuf(char *buf, int len) { return; }
void redraw_client(client_state_t *client, char *key_buffer, int key_len) { return; }
#endif

int main(int argc, char **argv) {

	struct sigaction act;
	act.sa_handler = int_handler;
	sigaction(SIGINT, &act, NULL);

	setlocale(LC_ALL, "en_US.UTF-8");

	client_state_t client = {0};

	if (argc == 3) {
		int ip_len = strlen(argv[1]);
		int port_len = strlen(argv[2]);
		char *ip_addr_str = argv[1];
		char *port_str = argv[2];

		if (ip_len > INET6_ADDRSTRLEN) {
			panic("IP address invalid! %s\n", ip_addr_str);
		}

		if (port_len > MAX_PORT_LEN) {
			panic("port invalid! %s\n", port_str);
		}

		char *stupid_ptr = NULL;
		size_t portret = strtol(port_str, &stupid_ptr, 10);
		if (!portret && port_str == stupid_ptr) {
			panic("Invalid port! %s\n", port_str);
		}


		client.port = (uint16_t)portret;
		memcpy(client.ip_addr, ip_addr_str, ip_len);
		client.ip_addr[ip_len] = 0;
		client.has_ip = true;
	}

	log_file = open("log", O_WRONLY | O_CREAT | O_APPEND, 0644);

	strcpy(client.auth_token, "0");
	client.conn.sd = -1;
	client.view_id = 0;
	client.view_type = VIEW_INTERNAL;

	client.max_channels = 10;
	client.max_pms = 10;
	client.max_users = 10;


	client.channel_hist = calloc(sizeof(channel_history_t), client.max_channels);
	client.private_hist = calloc(sizeof(pm_history_t), client.max_pms);
	client.users = calloc(sizeof(userref_t), client.max_users);
	cmd_scrollback_buffer = calloc(sizeof(cmd_buf_t), scrollback_max);

	internal_scrollback_buffer = malloc(sizeof(char *) * scrollback_max);
	page_scrollback_buffer = malloc(sizeof(char *) * scrollback_max);
	for (int i = 0; i < scrollback_max; i++) {
		internal_scrollback_buffer[i] = calloc(sizeof(char), MAX_MESSAGE_LEN + 1);
		page_scrollback_buffer[i] = calloc(sizeof(char), MAX_MESSAGE_LEN + 1);
	}

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_crypto_strings();

	SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
	if (!ctx) {
		panic("Unable to create SSL context\n");
	}

	client.ctx = ctx;

	int ret = SSL_CTX_load_verify_locations(ctx, "./tmp_ssl/rootCA.pem", NULL);
	if (ret != 1) {
		panic("Failed to get CA chain!\n");
	}

	init_client();


	while (!root_killme) {
		cmd_buf_t *cmdbuf = &cmd_scrollback_buffer[cmd_scrollback_idx];
		redraw_client(&client, cmdbuf->cbuf, cmdbuf->clen);

		// Don't bother sending if the conn isn't open!
		if (client.conn.sd != -1) {
			encrypt_data(&client.conn);
			send_data(&client.conn);
		}

		if (client.conn.sd == -1 && client.has_ip) {
			if (retry_count == 0) {
				print_line_internal("Connecting to %s:%d\n", client.ip_addr, client.port);
			}

			while (retry_count < 1) {
				int ret = setup_conn(&client, client.ip_addr, client.port);
				if (!ret) {
					break;
				}

				retry_count++;
			}
		}

		struct timeval spamtime;
		spamtime.tv_sec = 0;
		spamtime.tv_usec = 0;

		struct timeval *tv = NULL;
		if (client.conn.sd != -1 && !SSL_is_init_finished(client.conn.ssl) || (window_resized || redraw)) {
			tv = &spamtime;
		}

		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		int max_fd = 0;

		if (client.conn.sd != -1) {
			FD_SET(client.conn.sd, &rfds);
			max_fd = client.conn.sd;
		}

		int ret;
		do {
			ret = select(max_fd + 1, &rfds, NULL, NULL, tv);
		} while (ret == -1 && errno == EINTR && !root_killme);

		if (root_killme) {
			break;
		}

		if (ret == -1) {
			pdump("select");
		}


		if (FD_ISSET(0, &rfds)) {
			for (;;) {
				wint_t ch;
				int ret = get_wch(&ch);
				if (ret == ERR) {
					break;
				}

				if ((ret == KEY_CODE_YES && ch == KEY_BACKSPACE) || ch == 127) {
					if (cur_wchar <= 0) {
						continue;
					}

					cur_wchar--;

					int sz = cmdbuf->wbuf[cur_wchar].sz;
					int col_sz = cmdbuf->wbuf[cur_wchar].colsz;

					if (sz > 0) {
						int copy_size = (cmdbuf->wlen - cur_wchar);

						memmove(&cmdbuf->wbuf[cur_wchar], &cmdbuf->wbuf[cur_wchar + 1], copy_size * sizeof(wide_ref_t));
						cmdbuf->wlen -= 1;

						wchar_t wide_str[MAX_CHARS] = {0};
						for (int i = 0; i < cmdbuf->wlen; i++) {
							wide_str[i] = cmdbuf->wbuf[i].c;
						}

						cmdbuf->clen = wcstombs(cmdbuf->cbuf, wide_str, cmdbuf->wlen * sizeof(wchar_t));
						cur_col -= col_sz;
					}
					continue;
				}

				if (ret == KEY_CODE_YES) {

					if (ch == KEY_UP) {
						if (cmd_scrollback_idx == 0) {
							cmd_scrollback_idx = cmd_scrollback_len - 1;
						} else if (cmd_scrollback_idx == 1) {
							continue;
						} else {
							cmd_scrollback_idx--;
						}

						cur_col = 0;
						cur_wchar = 0;

						cmdbuf = &cmd_scrollback_buffer[cmd_scrollback_idx];
					} else if (ch == KEY_DOWN) {
						if (cmd_scrollback_idx == cmd_scrollback_len - 1) {
							cmd_scrollback_idx = 0;
						} else if (cmd_scrollback_idx == 0) {
							continue;
						} else {
							cmd_scrollback_idx++;
						}

						cur_col = 0;
						cur_wchar = 0;

						cmdbuf = &cmd_scrollback_buffer[cmd_scrollback_idx];
					} else if (ch == KEY_RIGHT) {
						if (cur_wchar >= cmdbuf->wlen) {
							continue;
						}

						int col_sz = cmdbuf->wbuf[cur_wchar].colsz;
						int sz = cmdbuf->wbuf[cur_wchar].sz;

						print_line_internal("%d, %d\n", col_sz, sz);

						cur_wchar++;
						cur_col += col_sz;
					} else if (ch == KEY_LEFT) {
						if (cur_wchar <= 0) {
							continue;
						}

						int col_sz = cmdbuf->wbuf[cur_wchar - 1].colsz;
						int sz = cmdbuf->wbuf[cur_wchar - 1].sz;

						print_line_internal("%d, %d\n", col_sz, sz);

						cur_wchar--;
						cur_col -= col_sz;
					} else if (ch ==  KEY_RESIZE) {
						window_resized = true;
					}

					continue;
				}

				if (ch == CTRL('a')) {
					cur_wchar = 0;
					cur_col = 0;
					continue;
				}

				if (ch == CTRL('e')) {
					cur_wchar = cmdbuf->wlen;

					int col_end = 0;
					for (int i = 0; i < cmdbuf->wlen; i++) {
						col_end += cmdbuf->wbuf[i].colsz;
					}

					cur_col = col_end;
					continue;
				}

				if (ch == 13) { // \n
					if (cmdbuf->clen ==  0) {
						continue;
					}

					cmdbuf->cbuf[cmdbuf->clen++] = '\n';

					token_t toks[MAX_TOKS] = {0};
					int toks_found = 0;
					int ret = tokenize_buffer(&client, true, cmdbuf->cbuf, cmdbuf->clen, toks, &toks_found);

					// Don't bother sending anything if the buffer can't be tokenized, or if there are no tokens
					if (ret != -1 && toks_found > 0) {

						// If there's nothing we can do with this buffer, try sending it to the server
						if (dispatch_internal_commands(&client, toks, toks_found) == INT_CMD_PASS) {
							send_to_conn(&client, cmdbuf->cbuf, cmdbuf->clen);
						}
					}

					cmdbuf->cbuf[cmdbuf->clen - 1] = 0;

					push_to_cmd_scrollback(cmdbuf);
					cmd_scrollback_idx = 0;

					memset(cmdbuf->cbuf, 0, cmdbuf->clen);
					memset(cmdbuf->wbuf, 0, sizeof(wide_ref_t) * cmdbuf->wlen);
					cmdbuf->clen = 0;
					cmdbuf->wlen = 0;
					cur_col = 0;
					cur_wchar = 0;

					continue;
				}

				char buf[4];
				int sz = wctomb(buf, ch);
				if (sz < 1) {
					print_line_error("Got invalid char? %d\n", ch);
					continue;
				}
				int colsz = wcwidth(ch);
				if (colsz < 1) {
					print_line_error("Got invalid char? %d\n", ch);
					continue;
				}

				// Looks a little goofy, but this needs to make sure that there's still space for the trailing \n
				if ((sz + cmdbuf->clen) > (MAX_MESSAGE_LEN - 1) || (cmdbuf->wlen + 1) > (MAX_CHARS - 1)) {
					print_line_error("Message at max size!\n");
					continue;
				}

				// make a hole for the new wchar to fit in
				for (int i = cmdbuf->wlen; i >= cur_wchar; i--) {
					cmdbuf->wbuf[i] = cmdbuf->wbuf[i - 1];
				}

				cmdbuf->wbuf[cur_wchar].c = ch;
				cmdbuf->wbuf[cur_wchar].sz = sz;
				cmdbuf->wbuf[cur_wchar].colsz = colsz;
				cmdbuf->wlen += 1;

				wchar_t wide_str[MAX_CHARS] = {0};
				for (int i = 0; i < cmdbuf->wlen; i++) {
					wide_str[i] = cmdbuf->wbuf[i].c;
				}

				cmdbuf->clen = wcstombs(cmdbuf->cbuf, wide_str, cmdbuf->wlen * sizeof(wchar_t));
				cur_col += colsz;
				cur_wchar++;
			}

			print_keybuf(cmdbuf->cbuf, cmdbuf->clen);
			wrefresh(chat_win);

			continue;
		}

		memset(encrypted_in_buffer, 0, MAX_IN_BUFFER);
		memset(clear_in_buffer, 0, MAX_IN_BUFFER);
		size_t clear_size = MAX_IN_BUFFER;

		int ret_bytes = 0;
		bool finished_read = false;
		bool killme = false;
		if (FD_ISSET(client.conn.sd, &rfds)) {
			while (ret_bytes < MAX_IN_BUFFER && !killme) {
				int ret = recv(client.conn.sd, encrypted_in_buffer + ret_bytes, MAX_IN_BUFFER - ret_bytes, 0);
				if (ret < 0) {
					if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
						break;
					}
					pdump("recv failed");
				} else if (ret == 0) {
					print_line_error("Server shut us down?\n");
					close_conn(&client);
					break;
				}
				ret_bytes += ret;
			}

			if (read_data(&client.conn, encrypted_in_buffer, ret_bytes, clear_in_buffer, &clear_size)) {
				panic("WTF\n");
			}
		}


		// Connection got dropped, return to select
		if (!client.conn.ssl) {
			continue;
		}

		// Handle mid-handshake nonsense
		if (!SSL_is_init_finished(client.conn.ssl)) {
			send_data(&client.conn);
			continue;

		// Validate server's cert with local chain
		} else if (!client.verified_server_cert) {
			X509 *cert = SSL_get_peer_certificate(client.conn.ssl);
			if (cert) {
				X509_free(cert);
			} else {
				print_line_internal("Server didn't give me a cert?\n");
				close_conn(&client);
				continue;
			}

			int ret = SSL_get_verify_result(client.conn.ssl);
			if (X509_V_OK != ret) {
				print_line_internal("Failed to verify cert from server!\n");
				close_conn(&client);
				continue;
			}

			print_line_internal("Successfully verified server cert\n");
			client.verified_server_cert = true;
		}

		if (clear_size < 0) {
			panic("Got bad buffer size?\n");
		}

/*
		if (clear_size > 0) {
			print_line_internal("READ: %d %.*s", clear_size, clear_size, clear_in_buffer);
		}
*/

		int off = 0;
		while (off < clear_size) {
			token_t toks[MAX_TOKS] = {0};
			int toks_found = 0;

			int ret = tokenize_buffer(&client, false, clear_in_buffer + off, clear_size - off, toks, &toks_found);
			if (ret == -1) {
				break;
			}
			off += ret;

			if (toks_found > 0) {
				dispatch_inbound_commands(&client, toks, toks_found);
			}
		}
	}

	endwin();
	return 0;
}
