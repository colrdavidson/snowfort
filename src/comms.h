#ifndef COMMS_H
#define COMMS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <sqlite3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define B64_PAD(x) ((((x) * 4) / 3) + 4)
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define MAX_CONNS 10
#define MAX_CHANNELS 10
#define MAX_CHANNEL_USERS 20
#define MAX_USERS 50
#define MAX_TOKS 10
#define MAX_MESSAGES 50
#define MAX_REG_TOK 30
#define MAX_B64_REG_TOK B64_PAD(30)

#define MAX_USER_ADDR (INET6_ADDRSTRLEN + 1 + sizeof(short))
#define MAX_PORT_LEN 5
#define MAX_REFNAME 20
#define MAX_COMMAND 20
#define MAX_B64_AUTH_TOKEN 80

#define MAX_CHARS (1024 * 2)
#define MAX_MESSAGE_LEN (MAX_CHARS * 4)

#define MAX_PASSWORD 40

// Maximum SSL record size
#define MAX_IN_BUFFER (16 * 1024)
#define MAX_OUT_BUFFER MAX_IN_BUFFER

// Man, this is ugly, but not as ugly as maintaining multiple lists
#define UNAUTH_COMMANDS \
	xtype(REGISTER), \
	xtype(LOGIN), \
	xtype(YEET)

#define NORMAL_COMMANDS \
	xtype(CHANNELS), \
	xtype(MYCHANNELS), \
	xtype(USERS), \
	xtype(MYPMS), \
	xtype(CHANNELUSERS), \
	xtype(JOIN), \
	xtype(LEAVE), \
	xtype(MSG), \
	xtype(TIME), \
	xtype(LIVE), \
	xtype(LIVECHECK), \
	xtype(HISTORY), \
	xtype(COUNTUNREAD), \
	xtype(MARKREAD)

#define ADMIN_COMMANDS \
	xtype(RELOAD), \
	xtype(GENTOKEN)

#define xtype(name) CMD_##name

typedef enum {
	UNAUTH_COMMANDS,
	NORMAL_COMMANDS,
	ADMIN_COMMANDS,
	CMD_PASS,
	CMD_ERROR
} cmd_t;

#undef xtype

typedef struct {
	int id;
	bool is_admin;
} user_t;

typedef struct {
	char *ptr;
	int size;
} token_t;

typedef struct __attribute__((__packed__)) {
	uint32_t user_id;
	uint32_t is_admin;
	time_t created;
} auth_token_t;

typedef struct {
	uint64_t id;
	char target[MAX_REFNAME + 1];
	char sender[MAX_REFNAME + 1];
	char data[MAX_MESSAGE_LEN + 1];
	int len;
	time_t created;
} message_t;

typedef enum {
	ERR_SUCCESS = 0,
	ERR_AUTH_INVALID,
	ERR_COMMAND_INVALID,
	ERR_COMMAND_FAILED,
	ERR_ARGS_INVALID,
	ERR_CHANNEL_INVALID,
	ERR_CHANNEL_FULL,
	ERR_TARGET_INVALID,
	ERR_DATA_INVALID,
	ERR_UNKNOWN
} conn_err_t;

#endif
