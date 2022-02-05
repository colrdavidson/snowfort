#include <stdio.h>
#include <fcntl.h>

#include "../comms.h"
#include "server.h"
#include "db.h"

// ipaddr + : + port
#define MAX_SALT 20

int db_randfd;

// THESE b64 funcs ARE STUPID, don't respect lengths properly, and require annoying mallocs. Need replacing
char *base64_encode(uint8_t *in, int len) {
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b64, in, len);
	BIO_flush(b64);

	BUF_MEM *bptr;
	BIO_get_mem_ptr(b64, &bptr);

	char *buf = malloc(bptr->length + 1);
	memcpy(buf, bptr->data, bptr->length);
	buf[bptr->length] = 0;

	BIO_free_all(b64);

	return buf;
}

int base64_decode(char *in, int len, uint8_t **out) {
	uint8_t *buffer = calloc(len, sizeof(uint8_t));

	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *bmem = BIO_new_mem_buf(in, -1);
	bmem = BIO_push(b64, bmem);
	BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

	int out_len = BIO_read(bmem, buffer, len);
	BIO_free_all(bmem);

	*out = buffer;

	return out_len;
}

void gen_random_bytes(uint8_t *buf, int size) {
	int ret = read(db_randfd, buf, size);
	if (ret != size) {
		panic("Failed to fill buffer!\n");
	}
}

// TODO: This is not a great password hashing func, I know. Too susceptible to rainbow table.
// Replace me later!
void sha256_bin(uint8_t *bin, int len, uint8_t *hash) {
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, bin, len);
	SHA256_Final(hash, &sha256);
}

char **get_user_list(sqlite3 *db) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT name FROM user WHERE deleted = FALSE;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	char **user_list = calloc(sizeof(char *), MAX_USERS);
	int i = 0;

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			char *username = (char *)sqlite3_column_text(stmt, 0);
			user_list[i] = malloc(MAX_REFNAME + 1);
			strcpy(user_list[i], username);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	return user_list;
}

int add_user(sqlite3 *db, char *username, char *password, bool is_admin) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO user(name, password, salt, is_admin, deleted) VALUES(?, ?, ?, ?, FALSE);", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	uint8_t salt[MAX_SALT];
	gen_random_bytes(salt, sizeof(salt));

	uint8_t salted_pass[MAX_PASSWORD + MAX_SALT];
	int pass_len = strlen(password);
	memcpy(salted_pass, password, pass_len);
	memcpy(salted_pass + pass_len, salt, sizeof(salt));


	uint8_t salted_passhash[SHA256_DIGEST_LENGTH];
	sha256_bin(salted_pass, pass_len + sizeof(salt), salted_passhash);

	char *b64_salted_passhash = base64_encode(salted_passhash, SHA256_DIGEST_LENGTH);
	char *b64_salt = base64_encode(salt, sizeof(salt));


	sqlite3_bind_text(stmt, 1, username, -1, NULL);
	sqlite3_bind_text(stmt, 2, b64_salted_passhash, -1, NULL);
	sqlite3_bind_text(stmt, 3, b64_salt, -1, NULL);
	sqlite3_bind_int(stmt, 4, is_admin);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		printf("%s\n", sqlite3_errmsg(db));
		ret = -1;
	} else {
		ret = sqlite3_last_insert_rowid(db);
	}

	sqlite3_finalize(stmt);

	free(b64_salted_passhash);
	free(b64_salt);

	return ret;
}

char *generate_auth_token(char *key, uint32_t user_id, uint32_t is_admin) {
	auth_token_t auth_token;
	auth_token.user_id  = user_id;
	auth_token.is_admin = is_admin;
	auth_token.created  = time(NULL);

	uint32_t digest_len = 0;
	uint8_t digest[EVP_MAX_MD_SIZE] = {0};
	HMAC(EVP_sha256(), key, strlen(key), (uint8_t *)&auth_token, sizeof(auth_token), digest, &digest_len);

	uint8_t *signed_auth_token = malloc(sizeof(auth_token) + digest_len);
	memcpy(signed_auth_token, &auth_token, sizeof(auth_token));
	memcpy(signed_auth_token + sizeof(auth_token), digest, digest_len);

	char *b64_token = base64_encode(signed_auth_token, sizeof(auth_token) + digest_len);
	free(signed_auth_token);

	return b64_token;
}

int validate_auth_token(char *key, char *b64_auth_blob, int b64_blob_len, auth_token_t *token) {
	if (b64_blob_len < sizeof(auth_token_t)) {
		printf("token blob too small to be valid!\n");
		return -1;
	}

	uint8_t *auth_blob = NULL;
	int len = base64_decode(b64_auth_blob, b64_blob_len, &auth_blob);
	if (len <= 0) {
		printf("invalid token\n");
		return -1;
	}

	uint8_t *blob_ptr = auth_blob;
	auth_token_t auth_token;
	memcpy(&auth_token.user_id, blob_ptr, sizeof(auth_token.user_id)); blob_ptr += sizeof(auth_token.user_id);
	memcpy(&auth_token.is_admin, blob_ptr, sizeof(auth_token.is_admin)); blob_ptr += sizeof(auth_token.is_admin);
	memcpy(&auth_token.created, blob_ptr, sizeof(auth_token.created)); blob_ptr += sizeof(auth_token.created);

	// A wild digest has appeared!
	uint32_t wild_digest_len = 0;
	uint8_t wild_digest[EVP_MAX_MD_SIZE] = {0};
	HMAC(EVP_sha256(), key, strlen(key), (uint8_t *)&auth_token, sizeof(auth_token), wild_digest, &wild_digest_len);

	int fresh_digest_len = len - sizeof(auth_token);
	if (fresh_digest_len != wild_digest_len) {
		printf("token blob is incorrect size\n");
		free(auth_blob);
		return -1;
	}

	uint8_t fresh_digest[EVP_MAX_MD_SIZE] = {0};
	memcpy(fresh_digest, blob_ptr, fresh_digest_len);
	free(auth_blob);

	if (memcmp(fresh_digest, wild_digest, wild_digest_len)) {
		printf("Token failed to validate\n");
		return -1;
	}


	memcpy(token, &auth_token, sizeof(auth_token));
	return 0;
}

user_t validate_auth(sqlite3 *db, char *username, char *password) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT id, password, salt, is_admin FROM user WHERE name = ? AND deleted = FALSE;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	user_t user = {0};
	sqlite3_bind_text(stmt, 1, username, -1, NULL);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return user;
	}

	int id = sqlite3_column_int(stmt, 0);
	char *db_pass = (char *)sqlite3_column_text(stmt, 1);
	char *saltstr = (char *)sqlite3_column_text(stmt, 2);
	bool is_admin = sqlite3_column_int(stmt, 3);

	uint8_t *salt = NULL;
	int saltstr_len = strlen(saltstr);
	int salt_len = base64_decode(saltstr, saltstr_len, &salt);
	if (salt_len != MAX_SALT) {
		panic("Salt is an invalid length %d!\n", salt_len);
	}

	uint8_t salted_pass[MAX_PASSWORD + MAX_SALT];
	int pass_len = strlen(password);
	memcpy(salted_pass, password, pass_len);
	memcpy(salted_pass + pass_len, salt, salt_len);

	uint8_t salted_passhash[SHA256_DIGEST_LENGTH];
	sha256_bin(salted_pass, pass_len + salt_len, salted_passhash);
	free(salt);

	char *b64_salted_passhash = base64_encode(salted_passhash, SHA256_DIGEST_LENGTH);

	int strret = strcmp(b64_salted_passhash, db_pass);
	free(b64_salted_passhash);
	sqlite3_finalize(stmt);

	if (strret) {
		return user;
	}

	user.id = id;
	user.is_admin = is_admin;

	return user;
}


void add_channel(sqlite3 *db, char *name) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO channel(name, deleted) VALUES(?, FALSE);", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_text(stmt, 1, name, -1, NULL);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
}

user_t register_new_user(sqlite3 *db, char *reg_token, char *username, char *password) {

	// Check if token exists in db
	sqlite3_stmt *token_check_stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT id, used, expiry, is_admin FROM registration_token WHERE str = ?;", -1, &token_check_stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	user_t user = {0};
	sqlite3_bind_text(token_check_stmt, 1, reg_token, -1, NULL);

	int    token_id     = -1;
	bool   used   = true;
	time_t expiry = 0;
	bool is_admin = false;

	int i = 0;
	for (;;) {
		ret = sqlite3_step(token_check_stmt);
		if (ret == SQLITE_ROW) {
			token_id = sqlite3_column_int(token_check_stmt, 0);
			used = sqlite3_column_int(token_check_stmt, 1);
			expiry = sqlite3_column_int(token_check_stmt, 2);
			is_admin = sqlite3_column_int(token_check_stmt, 3);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}
	if (i > 1) {
		panic("Too many tokens in db!\n");
	}
	sqlite3_finalize(token_check_stmt);

	if (i == 0) {
		printf("Token not found!\n");
		return user;
	}

	time_t now = time(NULL);
	if (expiry < now) {
		printf("Token has expired!\n");
		return user;
	}

	if (used) {
		printf("Token has been used!\n");
		return user;
	}


	// Token checks out, try adding user
	ret = add_user(db, username, password, is_admin);
	if (ret == -1) {
		return user;
	}
	int user_id = ret;


	// Mark token as used
	sqlite3_stmt *stmt;
	ret = sqlite3_prepare_v2(db, "UPDATE registration_token SET used = TRUE WHERE id = ?;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_int(stmt, 1, token_id);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);

	// Nice. We got a user!
	user.id = user_id;
	user.is_admin = is_admin;
	return user;
}

char *gen_reg_token(sqlite3 *db, bool is_admin) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO registration_token(str, expiry, used, is_admin) VALUES(?, strftime('%s', 'now', ?), FALSE, ?);", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	uint8_t token[MAX_REG_TOK];
	gen_random_bytes(token, sizeof(token));
	char *b64_token = base64_encode(token, sizeof(token));

	char *expiry_str;
	if (is_admin) {
		expiry_str = "+1 hour";
	} else {
		expiry_str = "+7 day";
	}

	printf("Token generated lives for %s\n", expiry_str);

	sqlite3_bind_text(stmt, 1, b64_token, -1, NULL);
	sqlite3_bind_text(stmt, 2, expiry_str, -1, NULL);
	sqlite3_bind_int(stmt, 3, is_admin);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
	return b64_token;
}


int join_channel(sqlite3 *db, int user_id, int channel) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO channel__user(user, channel) VALUES(?, ?);", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_int(stmt, 1, user_id);
	sqlite3_bind_int(stmt, 2, channel);

	ret = sqlite3_step(stmt);
	if (ret == SQLITE_CONSTRAINT) {
		sqlite3_finalize(stmt);
		return 0;
	} else if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
	return 1;
}

int leave_channel(sqlite3 *db, int user_id, int channel) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "DELETE FROM channel__user WHERE user = ? AND channel = ?;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_int(stmt, 1, user_id);
	sqlite3_bind_int(stmt, 2, channel);

	ret = sqlite3_step(stmt);
	if (ret == SQLITE_CONSTRAINT) {
		sqlite3_finalize(stmt);
		return 0;
	} else if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
	return 1;
}

char **get_channels(sqlite3 *db) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT channel.name FROM channel;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	char **channel_list = calloc(sizeof(char *), MAX_CHANNELS);
	int i = 0;

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			char *channelname = (char *)sqlite3_column_text(stmt, 0);
			channel_list[i] = malloc(MAX_REFNAME);
			strcpy(channel_list[i], channelname);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	return channel_list;
}

char **get_channels_for_user(sqlite3 *db, int user_id) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT channel.name FROM channel__user INNER JOIN channel ON channel__user.channel = channel.id WHERE channel__user.user = ?;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	char **channel_list = calloc(sizeof(char *), MAX_CHANNELS);
	int i = 0;

	sqlite3_bind_int(stmt, 1, user_id);
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			char *channelname = (char *)sqlite3_column_text(stmt, 0);
			channel_list[i] = calloc(MAX_REFNAME, sizeof(char));
			strncpy(channel_list[i], channelname, MAX_REFNAME);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	return channel_list;
}

int get_channel_usercount(sqlite3 *db, int channel_id) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM channel__user WHERE channel__user.channel = ?;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_int(stmt, 1, channel_id);

	int user_count = 0;
	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			user_count = sqlite3_column_int(stmt, 0);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);

	if (i > 1) {
		panic("Too many rows returned!\n");
	}

	return user_count;
}

bool check_user_in_channel(sqlite3 *db, int user_id, int channel_id) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM channel__user WHERE channel__user.user = ? AND channel__user.channel = ?;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_int(stmt, 1, user_id);
	sqlite3_bind_int(stmt, 2, channel_id);

	int user_count = 0;
	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			user_count = sqlite3_column_int(stmt, 0);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);

	if (i > 1) {
		panic("Too many rows returned!\n");
	}

	return user_count;
}

int get_total_cms(sqlite3 *db, int channel_id) {
	char *cm_total_query = "SELECT COUNT(*) FROM channel__message WHERE channel__message.channel = ?;";

	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, cm_total_query, -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}
	sqlite3_bind_int(stmt, 1, channel_id);

	int total_cms = 0;
	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > 1) {
				panic("Too many counts!\n");
			}

			total_cms = sqlite3_column_int(stmt, 0);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	return total_cms;
}

int get_username_for_id(sqlite3 *db, int user_id, char *buffer) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT name FROM user WHERE user.id = ? AND user.deleted = FALSE;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_int(stmt, 1, user_id);

	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			char *username = (char *)sqlite3_column_text(stmt, 0);
			strncpy(buffer, username, MAX_REFNAME);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			sqlite3_finalize(stmt);
			return -1;
		}
	}

	sqlite3_finalize(stmt);

	if (i > 1) {
		panic("Too many users returned!\n");
	}

	return 0;
}

int get_user_id(sqlite3 *db, char *username) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT id FROM user WHERE user.name = ? AND user.deleted = FALSE;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_text(stmt, 1, username, -1, NULL);

	int user_id = 0;
	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			user_id = sqlite3_column_int(stmt, 0);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);

	if (i > 1) {
		panic("Too many users returned!\n");
	}

	return user_id;
}

int get_channel_id(sqlite3 *db, char *channelname) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT id FROM channel WHERE channel.name = ?;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_text(stmt, 1, channelname, -1, NULL);

	int channel_id = 0;
	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			channel_id = sqlite3_column_int(stmt, 0);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);

	if (i > 1) {
		panic("Too many channels returned!\n");
	}

	return channel_id;
}

int *get_users_in_channel(sqlite3 *db, int channel_id) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT user.id FROM user INNER JOIN channel__user ON user.id = channel__user.user WHERE channel__user.channel = ?;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	int *user_list = calloc(sizeof(int), MAX_CHANNEL_USERS);
	int i = 0;

	sqlite3_bind_int(stmt, 1, channel_id);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > MAX_CHANNEL_USERS) {
				panic("Too many users in channel!\n");
			}

			user_list[i] = sqlite3_column_int(stmt, 0);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	return user_list;
}

char **get_usernames_in_channel(sqlite3 *db, int channel_id) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "SELECT user.name FROM user INNER JOIN channel__user ON user.id = channel__user.user WHERE channel__user.channel = ?;", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	char **user_list = calloc(sizeof(char *), MAX_CHANNEL_USERS);
	int i = 0;

	sqlite3_bind_int(stmt, 1, channel_id);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > MAX_CHANNEL_USERS) {
				panic("Too many users in channel!\n");
			}

			char *username = (char *)sqlite3_column_text(stmt, 0);
			user_list[i] = calloc(MAX_REFNAME, sizeof(char));
			strncpy(user_list[i], username, MAX_REFNAME);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	return user_list;
}

uint64_t store_channel_message(sqlite3 *db, int channel_id, int sender_id, char *msg, int msg_len) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO message(data, created) VALUES(?, strftime('%s', 'now'));", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_text(stmt, 1, msg, msg_len, NULL);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
	uint64_t message_id = sqlite3_last_insert_rowid(db);

	sqlite3_stmt *stmt2;
	ret = sqlite3_prepare_v2(db, "INSERT INTO channel__message(sender, channel, message) VALUES(?, ?, ?);", -1, &stmt2, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_int(stmt, 1, sender_id);
	sqlite3_bind_int(stmt, 2, channel_id);
	sqlite3_bind_int(stmt, 3, message_id);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);

	return message_id;
}

uint64_t store_pm(sqlite3 *db, int pm_channel_id, bool to_user2, char *msg, int msg_len) {
	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO message(data, created) VALUES(?, strftime('%s', 'now'));", -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_text(stmt, 1, msg, msg_len, NULL);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
	uint64_t message_id = sqlite3_last_insert_rowid(db);

	sqlite3_stmt *stmt2;
	ret = sqlite3_prepare_v2(db, "INSERT INTO pm_channel__message(pm_channel, message, to_user2) VALUES(?, ?, ?);", -1, &stmt2, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_int(stmt2, 1, pm_channel_id);
	sqlite3_bind_int(stmt2, 2, message_id);
	sqlite3_bind_int(stmt2, 3, to_user2);

	ret = sqlite3_step(stmt2);
	if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt2);

	return message_id;
}

pm_channel_t get_pm_channel(sqlite3 *db, int in_user1, int in_user2) {
	sqlite3_stmt *stmt;

	int ret = sqlite3_prepare_v2(db, "SELECT id, user1, user2 FROM pm_channel WHERE ((user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?));", -1, &stmt, 0);

	sqlite3_bind_int(stmt, 1, in_user1);
	sqlite3_bind_int(stmt, 2, in_user2);
	sqlite3_bind_int(stmt, 3, in_user2);
	sqlite3_bind_int(stmt, 4, in_user1);

	uint64_t pm_channel_id = 0;
	uint64_t out_user1 = 0;
	uint64_t out_user2 = 0;
	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > 1) {
				panic("Too many pm channels!\n");
			}

			pm_channel_id = sqlite3_column_int(stmt, 0);
			out_user1 = sqlite3_column_int(stmt, 1);
			out_user2 = sqlite3_column_int(stmt, 2);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);

	pm_channel_t pm_chan;
	pm_chan.id = pm_channel_id;
	pm_chan.user1 = out_user1;
	pm_chan.user2 = out_user2;

	return pm_chan;
}

uint64_t add_pm_channel(sqlite3 *db, int user1, int user2) {
	sqlite3_stmt *stmt;

	int ret = sqlite3_prepare_v2(db, "INSERT INTO pm_channel(user1, user2, unread1, unread2) VALUES(?, ?, strftime('%s', 'now'), strftime('%s', 'now'));", -1, &stmt, 0);

	sqlite3_bind_int(stmt, 1, user1);
	sqlite3_bind_int(stmt, 2, user2);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
	uint64_t pm_channel_id = sqlite3_last_insert_rowid(db);

	return pm_channel_id;
}

char **get_pm_list_for_user(sqlite3 *db, int user_id) {
	sqlite3_stmt *stmt;

    char *pm_query = "SELECT user.name "
					 "FROM pm_channel "
					 "INNER JOIN user ON user.id = pm_channel.user1 "
					 "WHERE pm_channel.user2 = ? "
					 "UNION "
					 "SELECT user.name "
					 "FROM pm_channel "
					 "INNER JOIN user ON user.id = pm_channel.user2 "
					 "WHERE pm_channel.user1 = ?;";

	int ret = sqlite3_prepare_v2(db, pm_query, -1, &stmt, 0);

	char **user_list = calloc(sizeof(char *), MAX_USERS);
	int i = 0;

	sqlite3_bind_int(stmt, 1, user_id);
	sqlite3_bind_int(stmt, 2, user_id);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > MAX_USERS) {
				panic("Too many pm'd users!\n");
			}

			char *username = (char *)sqlite3_column_text(stmt, 0);
			user_list[i] = calloc(MAX_REFNAME, sizeof(char));
			strncpy(user_list[i], username, MAX_REFNAME);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	return user_list;
}

int get_total_pms(sqlite3 *db, int pm_channel_id) {
	char *pm_total_query = "SELECT COUNT(*) FROM pm_channel__message WHERE pm_channel__message.pm_channel = ?;";

	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, pm_total_query, -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}
	sqlite3_bind_int(stmt, 1, pm_channel_id);

	int total_pms = 0;
	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > 1) {
				panic("Too many counts!\n");
			}

			total_pms = sqlite3_column_int(stmt, 0);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	return total_pms;
}

message_t *get_pm_history(sqlite3 *db, int pm_channel_id, int offset, int *chunk_size) {
	char *pm_query = "SELECT message.id, usr1.name, usr2.name, pm_channel__message.to_user2, message.data, message.created "
					 "FROM pm_channel__message "
					 "INNER JOIN message ON pm_channel__message.message = message.id "
					 "INNER JOIN pm_channel ON pm_channel__message.pm_channel = pm_channel.id "
					 "INNER JOIN user AS usr1 ON usr1.id = pm_channel.user1 "
					 "INNER JOIN user AS usr2 ON usr2.id = pm_channel.user2 "
					 "WHERE pm_channel__message.pm_channel = ? ORDER BY message.created DESC LIMIT ? OFFSET ?;";


	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, pm_query, -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}
	sqlite3_bind_int(stmt, 1, pm_channel_id);
	sqlite3_bind_int(stmt, 2, MAX_MESSAGES);
	sqlite3_bind_int(stmt, 3, offset);

	message_t *message_list = calloc(sizeof(message_t), MAX_MESSAGES);

	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > MAX_MESSAGES) {
				panic("Too many messages in PMs!\n");
			}

			int message_id  = sqlite3_column_int(stmt, 0);
			char *user1     = (char *)sqlite3_column_text(stmt, 1);
			char *user2     = (char *)sqlite3_column_text(stmt, 2);
			bool to_user2   = sqlite3_column_int(stmt, 3);
			int message_len = sqlite3_column_bytes(stmt, 4);
			char *message   = (char *)sqlite3_column_text(stmt, 4);
			time_t created  = sqlite3_column_int(stmt, 5);

			if (message_len > MAX_MESSAGE_LEN) {
				panic("Message in DB too large!\n");
			}

			message_list[i].id = message_id;

			if (to_user2) {
				strncpy(message_list[i].target, user2, MAX_REFNAME);
				strncpy(message_list[i].sender, user1, MAX_REFNAME);
			} else {
				strncpy(message_list[i].target, user1, MAX_REFNAME);
				strncpy(message_list[i].sender, user2, MAX_REFNAME);
			}

			memcpy(message_list[i].data, message, message_len);
			message_list[i].len = message_len;
			message_list[i].created = created;

			printf("Retrieved (%d) %.*s\n", message_len, message_len, message);

			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	*chunk_size = i;

	sqlite3_finalize(stmt);
	return message_list;
}

int get_total_unread_pms(sqlite3 *db, int pm_channel_id, bool is_user1) {
	char *pm_total_query;

	if (is_user1) {
		pm_total_query = "SELECT COUNT(*) "
						 "FROM pm_channel__message "
						 "INNER JOIN message ON pm_channel__message.message = message.id "
						 "INNER JOIN pm_channel ON pm_channel__message.pm_channel = pm_channel.id "
						 "WHERE pm_channel__message.pm_channel = ? AND pm_channel.unread1 < message.created;";
	} else {
		pm_total_query = "SELECT COUNT(*) "
						 "FROM pm_channel__message "
						 "INNER JOIN message ON pm_channel__message.message = message.id "
						 "INNER JOIN pm_channel ON pm_channel__message.pm_channel = pm_channel.id "
						 "WHERE pm_channel__message.pm_channel = ? AND pm_channel.unread2 < message.created;";
	}

	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, pm_total_query, -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_int(stmt, 1, pm_channel_id);

	int total_pms = 0;
	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > 1) {
				panic("Too many counts!\n");
			}

			total_pms = sqlite3_column_int(stmt, 0);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	return total_pms;
}

message_t *get_channel_history(sqlite3 *db, int channel_id, int offset, int *chunk_size) {
	char *cm_query = "SELECT message.id, user.name, message.data, message.created "
					 "FROM channel__message "
					 "INNER JOIN message ON channel__message.message = message.id "
					 "INNER JOIN user ON user.id = channel__message.sender "
					 "WHERE channel__message.channel = ? ORDER BY message.created DESC LIMIT ? OFFSET ?;";

	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, cm_query, -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_bind_int(stmt, 1, channel_id);
	sqlite3_bind_int(stmt, 2, MAX_MESSAGES);
	sqlite3_bind_int(stmt, 3, offset);

	message_t *message_list = calloc(sizeof(message_t), MAX_MESSAGES);

	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > MAX_MESSAGES) {
				panic("Too many messages in channel!\n");
			}

			int message_id  = sqlite3_column_int(stmt, 0);
			char *sender    = (char *)sqlite3_column_text(stmt, 1);
			int message_len = sqlite3_column_bytes(stmt, 2);
			char *message   = (char *)sqlite3_column_text(stmt, 2);
			time_t created  = sqlite3_column_int(stmt, 3);

			if (message_len > MAX_MESSAGE_LEN) {
				panic("Message in DB too large!\n");
			}

			message_list[i].id = message_id;

			strncpy(message_list[i].sender, sender, MAX_REFNAME);
			memcpy(message_list[i].data, message, message_len);
			message_list[i].len = message_len;
			message_list[i].created = created;


			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	printf("Got %d messages\n", i);

	*chunk_size = i;

	sqlite3_finalize(stmt);
	return message_list;
}

int get_unread_cms_since(sqlite3 *db, int channel_id, int unread_ts) {
	char *cm_total_query = "SELECT COUNT(*) "
						   "FROM channel__message "
						   "INNER JOIN message ON channel__message.message = message.id "
						   "WHERE channel__message.channel = ? AND message.created > ?;";

	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, cm_total_query, -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}
	sqlite3_bind_int(stmt, 1, channel_id);
	sqlite3_bind_int(stmt, 2, unread_ts);

	int total_cms = 0;
	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > 1) {
				panic("Too many totals!\n");
			}

			total_cms = sqlite3_column_int(stmt, 0);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	return total_cms;
}

int get_total_unread_cms(sqlite3 *db, int channel_id, int user_id) {
	char *cm_unread_query = "SELECT unread "
						    "FROM channel__user "
						    "WHERE channel = ? AND user = ?;";

	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, cm_unread_query, -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}
	sqlite3_bind_int(stmt, 1, channel_id);
	sqlite3_bind_int(stmt, 2, user_id);

	int unread = 0;
	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > 1) {
				panic("Too many unread timers!\n");
			}

			unread = sqlite3_column_int(stmt, 0);
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}
	sqlite3_finalize(stmt);

	int total_cms = get_unread_cms_since(db, channel_id, unread);

	return total_cms;
}

msg_read_t *get_channel_unread_list(sqlite3 *db, int user_id) {
	char *cm_unread_query = "SELECT channel.id, channel.name, channel__user.unread "
						    "FROM channel__user "
							"INNER JOIN channel ON channel__user.channel = channel.id "
						    "WHERE channel__user.user = ?;";

	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, cm_unread_query, -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}
	sqlite3_bind_int(stmt, 1, user_id);

	msg_read_t *channel_list = calloc(sizeof(msg_read_t), MAX_CHANNELS);

	int i = 0;
	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > MAX_CHANNELS) {
				panic("Too many unread timers!\n");
			}

			int channel_id = sqlite3_column_int(stmt, 0);

			char *channelname = (char *)sqlite3_column_text(stmt, 1);
			strcpy(channel_list[i].name, channelname);

			int unread_ts = sqlite3_column_int(stmt, 2);
			int total_cms = get_unread_cms_since(db, channel_id, unread_ts);
			channel_list[i].unread = total_cms;
			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}
	sqlite3_finalize(stmt);


	return channel_list;
}

void channel_mark_read(sqlite3 *db, int channel_id, int user_id) {
	char *cm_mark_read_query = "UPDATE channel__user "
						    "SET unread = strftime('%s', 'now') "
						    "WHERE channel = ? AND user = ?;";

	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, cm_mark_read_query, -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}
	sqlite3_bind_int(stmt, 1, channel_id);
	sqlite3_bind_int(stmt, 2, user_id);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
}

msg_read_t *get_pm_unread_list(sqlite3 *db, int user_id) {
    char *pm_query = "SELECT pm_channel.id, user.name, FALSE "
					 "FROM pm_channel "
					 "INNER JOIN user ON user.id = pm_channel.user1 "
					 "WHERE pm_channel.user2 = ? "
					 "UNION "
					 "SELECT pm_channel.id, user.name, TRUE "
					 "FROM pm_channel "
					 "INNER JOIN user ON user.id = pm_channel.user2 "
					 "WHERE pm_channel.user1 = ?;";


	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, pm_query, -1, &stmt, 0);

	msg_read_t *user_list = calloc(sizeof(msg_read_t), MAX_USERS);
	int i = 0;

	sqlite3_bind_int(stmt, 1, user_id);
	sqlite3_bind_int(stmt, 2, user_id);

	for (;;) {
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			if (i > MAX_USERS) {
				panic("Too many pm'd users!\n");
			}

			int pm_channel_id = sqlite3_column_int(stmt, 0);

			char *username = (char *)sqlite3_column_text(stmt, 1);
			strcpy(user_list[i].name, username);

			bool is_user1 = sqlite3_column_int(stmt, 2);
			int unread_count = get_total_unread_pms(db, pm_channel_id, is_user1);
			user_list[i].unread = unread_count;

			i++;
		} else if (ret == SQLITE_DONE) {
			break;
		} else {
			panic(sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	return user_list;
}

void pm_channel_mark_read(sqlite3 *db, int pm_channel_id, bool is_user1) {
	char *pm_mark_read_query;
	if (is_user1) {
		pm_mark_read_query = "UPDATE pm_channel "
							 "SET unread1 = strftime('%s', 'now') "
							 "WHERE id = ?;";
	} else {
		pm_mark_read_query = "UPDATE pm_channel "
							 "SET unread2 = strftime('%s', 'now') "
							 "WHERE id = ?;";
	}

	sqlite3_stmt *stmt;
	int ret = sqlite3_prepare_v2(db, pm_mark_read_query, -1, &stmt, 0);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}
	sqlite3_bind_int(stmt, 1, pm_channel_id);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		panic(sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
}

char db_target[] = "server.db";
void setup_database(int randfd) {
	sqlite3 *db;

	bool fresh_db = false;
	int ret = sqlite3_open_v2(db_target, &db, SQLITE_OPEN_READWRITE, NULL);
	if (ret) {
		sqlite3_close(db);
		fresh_db = true;

		printf("No database found, setting a new one up!\n");
		ret = sqlite3_open_v2(db_target, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
		if (ret) {
			panic(sqlite3_errmsg(db));
		}
	}

	db_randfd = randfd;
	if (!fresh_db) {
		return;
	}

	char *table_def = "CREATE TABLE user(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, password TEXT NOT NULL, salt TEXT NOT NULL, is_admin BOOL, deleted BOOL);"
					  "CREATE TABLE channel(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, deleted BOOL);"
					  "CREATE TABLE message(id INTEGER PRIMARY KEY, data TEXT NOT NULL, created INTEGER, deleted BOOL);"
					  "CREATE TABLE channel__user(id INTEGER PRIMARY KEY, user INTEGER, channel INTEGER, unread INTEGER, FOREIGN KEY(user) REFERENCES user(id), FOREIGN KEY(channel) REFERENCES channel(id), UNIQUE(user, channel));"
					  "CREATE TABLE channel__message(id INTEGER PRIMARY KEY, channel INTEGER, sender INTEGER, message INTEGER, FOREIGN KEY(sender) REFERENCES user(id), FOREIGN KEY(channel) REFERENCES channel(id), FOREIGN KEY(message) REFERENCES message(id));"
					  "CREATE TABLE pm_channel(id INTEGER PRIMARY KEY, user1 INTEGER, user2 INTEGER, unread1 INTEGER, unread2 INTEGER, FOREIGN KEY(user1) REFERENCES user(id), FOREIGN KEY(user2) REFERENCES user(id), UNIQUE(user1, user2));"
					  "CREATE TABLE pm_channel__message(id INTEGER PRIMARY KEY, pm_channel INTEGER, message INTEGER, to_user2 BOOL, FOREIGN KEY(pm_channel) REFERENCES pm_channel(id), FOREIGN KEY(message) REFERENCES message(id), UNIQUE(pm_channel, message));"
					  "CREATE TABLE registration_token(id INTEGER PRIMARY KEY, str TEXT UNIQUE NOT NULL, expiry INTEGER, used BOOL, is_admin BOOL);";

	char *error_msg = NULL;
	ret = sqlite3_exec(db, table_def, 0, 0, &error_msg);
	if (ret) {
		panic(sqlite3_errmsg(db));
	}


	char *setup_token = gen_reg_token(db, true);
	printf("Inital setup token: %s\n", setup_token);
	free(setup_token);

	// Preconfig setup for ease of testing
	add_channel(db, "eng-root");
	add_channel(db, "offtopic");
	add_channel(db, "💩");

	sqlite3_close(db);
}

void open_db(sqlite3 **db) {
	int ret = sqlite3_open_v2(db_target, db, SQLITE_OPEN_READWRITE, NULL);
	if (ret) {
		panic("No existing database?\n");
	}
}
