#ifndef DB_H
#define DB_H

typedef struct {
	uint64_t id;
	uint64_t user1;
	uint64_t user2;
} pm_channel_t;

typedef struct {
	char name[MAX_REFNAME + 1];
	int unread;
} msg_read_t;

char *gen_reg_token(sqlite3 *db, bool is_admin);

user_t validate_auth(sqlite3 *db, char *username, char *password);
user_t register_new_user(sqlite3 *db, char *reg_token, char *username, char *password);
char *generate_auth_token(char *key, uint32_t user_id, uint32_t is_admin);
int validate_auth_token(char *key, char *b64_auth_blob, int b64_blob_len, auth_token_t *token);
int get_user_id(sqlite3 *db, char *username);
int get_username_for_id(sqlite3 *db, int user_id, char *buffer);
char **get_user_list(sqlite3 *db);

int join_channel(sqlite3 *db, int user_id, int channel);
int leave_channel(sqlite3 *db, int user_id, int channel);
char **get_channels(sqlite3 *db);
char **get_channels_for_user(sqlite3 *db, int user_id);
char **get_usernames_in_channel(sqlite3 *db, int channel_id);
int *get_users_in_channel(sqlite3 *db, int channel_id);
int get_channel_id(sqlite3 *db, char *channelname);
int get_channel_usercount(sqlite3 *db, int channel_id);
bool check_user_in_channel(sqlite3 *db, int user_id, int channel_id);

uint64_t store_channel_message(sqlite3 *db, int channel_id, int sender_id, char *msg, int msg_len);
message_t *get_channel_history(sqlite3 *db, int channel_id, int offset, int *chunk_size);
int get_total_cms(sqlite3 *db, int channel_id);
int get_total_unread_cms(sqlite3 *db, int channel_id, int user_id);
msg_read_t *get_channel_unread_list(sqlite3 *db, int user_id);
void channel_mark_read(sqlite3 *db, int channel_id, int user_id);

uint64_t add_pm_channel(sqlite3 *db, int user1, int user2);
char **get_pm_list_for_user(sqlite3 *db, int user_id);
message_t *get_pm_history(sqlite3 *db, int pm_channel_id, int offset, int *chunk_size);
uint64_t store_pm(sqlite3 *db, int pm_channel_id, bool to_user2, char *msg, int msg_len);
int get_total_pms(sqlite3 *db, int pm_channel_id);
int get_total_unread_pms(sqlite3 *db, int pm_channel_id, bool is_user1);
pm_channel_t get_pm_channel(sqlite3 *db, int in_user1, int in_user2);
msg_read_t *get_pm_unread_list(sqlite3 *db, int user_id);
void pm_channel_mark_read(sqlite3 *db, int pm_channel_id, bool is_user1);

void setup_database(int randfd);
void open_db(sqlite3 **db);

#endif
