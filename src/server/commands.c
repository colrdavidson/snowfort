#include <ctype.h>

#include "../comms.h"
#include "server.h"
#include "db.h"

int cmd_users(engine_state_t *engine, conn_t *conn, int args_found) {
	if (args_found != 0) {
		send_conn_response(ERR_ARGS_INVALID, conn, ":incorrect number of args\n");
		return -1;
	}
	char **user_list = get_user_list(conn->db);

	// space for comma separated channels ex: #fee, #fi, #fo, #fum
	char users_str[(MAX_USERS * MAX_REFNAME) + (MAX_USERS * 2)] = {0};
	int plop_iter = 0;

	int i = 0;
	for (; i < MAX_USERS; i++) {
		if (!user_list[i]) {
			break;
		}

		char *fmtstr = "%s, ";
		if (i + 1 >= MAX_USERS || !user_list[i + 1]) {
			fmtstr = "%s";
		}

		plop_iter += snprintf(users_str + plop_iter, sizeof(users_str) - plop_iter, fmtstr, user_list[i]);
		free(user_list[i]);
	}
	free(user_list);

	char tmp[MAX_OUT_BUFFER] = {0};
	sprintf(tmp, "\\users :%s\n", users_str);
	send_conn_response(0, conn, tmp);

	return 0;
}

int cmd_channels(engine_state_t *engine, conn_t *conn, int args_found) {
	if (args_found != 0) {
		send_conn_response(ERR_ARGS_INVALID, conn, ":incorrect number of args\n");
		return -1;
	}

	char **channel_list = get_channels(conn->db);

	// space for comma separated channels ex: #fee, #fi, #fo, #fum
	char channel_str[(MAX_CHANNELS * MAX_REFNAME) + (MAX_CHANNELS * 2)] = {0};
	int plop_iter = 0;
	for (int i = 0; i < MAX_CHANNELS; i++) {
		if (!channel_list[i]) {
			break;
		}

		char *fmtstr = "#%s, ";
		if (i + 1 >= MAX_CHANNELS || !channel_list[i + 1]) {
			fmtstr = "#%s";
		}

		plop_iter += sprintf(channel_str + plop_iter, fmtstr, channel_list[i]);
		free(channel_list[i]);
	}
	free(channel_list);

	char tmp[MAX_OUT_BUFFER] = {0};
	sprintf(tmp, "\\channels :%s\n", channel_str);
	send_conn_response(0, conn, tmp);

	return 0;
}

int cmd_livecheck(engine_state_t *engine, conn_t *conn, int args_found) {
	if (args_found != 0) {
		send_conn_response(ERR_ARGS_INVALID, conn, ":incorrect number of args\n");
		return -1;
	}

	int user_len = 0;
	char **user_list = calloc(sizeof(char *), MAX_CONNS);

	pthread_mutex_lock(&engine->conn_lock);
	for (int i = 0; i < MAX_CONNS; i++) {
		// skip yourself, you know you are live
		if (engine->conns[i].id == conn->id) {
			continue;
		}

		// don't bother including connections that haven't authed yet
		if (engine->conns[i].id == -1) {
			continue;
		}

		user_list[user_len++] = engine->conns[i].name;
	}
	pthread_mutex_unlock(&engine->conn_lock);

	// space for comma separated users ex: cloin, jeff, zappyhippo
	char users_str[(MAX_USERS * MAX_REFNAME) + (MAX_USERS * 2)] = {0};
	int plop_iter = 0;
	for (int i = 0; i < user_len; i++) {
		char *fmtstr = "%s, ";
		if (i + 1 >= user_len) {
			fmtstr = "%s";
		}

		plop_iter += sprintf(users_str + plop_iter, fmtstr, user_list[i]);
	}
	free(user_list);

	char tmp[MAX_OUT_BUFFER] = {0};
	sprintf(tmp, "\\livecheck :%s\n", users_str);
	send_conn_response(0, conn, tmp);
	return 0;
}

int process_inbound(engine_state_t *engine, conn_t *conn, char *clear_buffer, int len, token_t *toks, int *toks_len) {
	int clear_off = 0;
	*toks_len = 0;

	// Command Parsing
	if (clear_buffer[0] == '\0') {
		send_conn_response(ERR_COMMAND_INVALID, conn, ":Empty string?\n");
		return -1;
	}

	int toks_found = 0;
	bool started_token = false;
	bool started_terminator = false;
	int i = 0;
	for (;;) {
		while (clear_buffer[i] == ' ' && i < len) { // eat until not spaces
			i++;
		}

		if (clear_buffer[i] == '\n') {
			if (started_token) {
				toks[toks_found].size = clear_buffer + i - toks[toks_found].ptr;
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
		toks[toks_found].ptr = clear_buffer + i;

		if (clear_buffer[i] == ':') { // Must start the token with the terminator to trigger this
			started_terminator = true;
			toks[toks_found].ptr++;
			i++;
		}

		while (clear_buffer[i] != '\n' && clear_buffer[i] != '\0' && i < len) { // consume until token finish
			// Once : is hit, stop using whitespace as a delim
			if (!started_terminator && clear_buffer[i] == ' ') {
				break;
			}

			i++;
		}
		if (i >= len) {
			break;
		}

		toks[toks_found].size = clear_buffer + i - toks[toks_found].ptr;
		toks_found++;
		started_token = false;

		if (toks_found > MAX_TOKS) {
			send_conn_response(ERR_COMMAND_INVALID, conn, ":Too many tokens?\n");
			return -1;
		}
	}
	*toks_len = toks_found;
	clear_off = i;

/*
	//printf("%.*s\n", len, clear_buffer);
	for (int i = 0; i < toks_found; i++) {
		printf("[%d, {%.*s}, size: %d]\n", i, toks[i].size, toks[i].ptr, toks[i].size);
	}
*/

	if (!toks_found) {
		send_conn_response(ERR_COMMAND_INVALID, conn, ":Sent an empty msg?\n");
	}

	return clear_off;
}

#define xtype(name) #name
char *unauth_cmd_strs[] = { UNAUTH_COMMANDS };
int unauth_cmd_str_len = sizeof(unauth_cmd_strs) / sizeof(char *);

char *normal_cmd_strs[] = { NORMAL_COMMANDS };
int normal_cmd_str_len = sizeof(normal_cmd_strs) / sizeof(char *);

char *admin_cmd_strs[] = { ADMIN_COMMANDS };
int admin_cmd_str_len = sizeof(admin_cmd_strs) / sizeof(char *);

cmd_t select_command(engine_state_t *engine, conn_t *conn, token_t *toks, int toks_len) {

	cmd_t command_type = CMD_ERROR;
	int cmd_str_off = 0;

	if (toks_len < 2) {
		send_conn_response(ERR_COMMAND_INVALID, conn, ":Every valid command has at least 2 tokens!\n");
		return CMD_PASS;
	}


	if (toks[0].size > MAX_B64_AUTH_TOKEN) {
		send_conn_response(ERR_AUTH_INVALID, conn, ":invalid auth token\n");
		return CMD_PASS;
	}

	if (!(toks[0].ptr[0] == '0' && toks[0].size == 1)) {
		auth_token_t token = {0};

		char auth_token[MAX_B64_AUTH_TOKEN] = {0};
		if (toks[0].size > MAX_B64_AUTH_TOKEN) {
			send_conn_response(ERR_AUTH_INVALID, conn, ":invalid auth token\n");
			return CMD_PASS;
		}
		memcpy(auth_token, toks[0].ptr, toks[0].size);

		int ret2 = validate_auth_token(engine->hkey, auth_token, toks[0].size, &token);
		if (ret2) {
			send_conn_response(ERR_AUTH_INVALID, conn, ":invalid auth token\n");
			return CMD_PASS;
		}

		bool reconnected = (conn->id == -1);
		char username[MAX_REFNAME + 1] = {0};
		if (get_username_for_id(conn->db, token.user_id, username) == -1) {
			panic("Got valid auth token, but no username!\n");
		}

		memset(conn->name, 0, MAX_REFNAME);
		strcpy(conn->name, username);
		conn->id = token.user_id;
		conn->is_admin = token.is_admin;

		if (reconnected) {
			printf("User %d (admin: %d) reconnected on socket %d @ %s\n", conn->id, conn->is_admin, conn->sd, conn->addr);
		}
	}

	// Chop \ off of command, and build args list
	char command[MAX_COMMAND + 1] = {0};
	if ((toks[1].size - 1) > MAX_COMMAND) {
		send_conn_response(ERR_COMMAND_INVALID, conn, ":Command is too long!\n");
		return CMD_PASS;
	}
	memcpy(command, toks[1].ptr + 1, toks[1].size - 1);


	for (int i = 0; i < unauth_cmd_str_len; i++) {
		if (!strcasecmp(unauth_cmd_strs[i], command)) {
			return i + cmd_str_off;
		}
	}

	if (command_type == CMD_ERROR && conn->id == -1) {
		send_conn_response(ERR_AUTH_INVALID, conn, ":Please log in!\n");
		return CMD_PASS;
	}

	// Check to see if command is in the list of normal / authed user commands
	cmd_str_off += unauth_cmd_str_len;
	for (int i = 0; i < normal_cmd_str_len; i++) {
		if (!strcasecmp(normal_cmd_strs[i], command)) {
			return i + cmd_str_off;
		}
	}


	// If user is admin, check to see if command is in the list of admin commands
	if (!conn->is_admin) {
		return CMD_ERROR;
	}

	cmd_str_off += normal_cmd_str_len;
	for (int i = 0; i < admin_cmd_str_len; i++) {
		if (!strcasecmp(admin_cmd_strs[i], command)) {
			return i + cmd_str_off;
		}
	}

	return CMD_ERROR;
}

int dispatch_command(engine_state_t *engine, conn_t *conn, token_t *toks, int toks_len) {
	cmd_t command_type = select_command(engine, conn, toks, toks_len);
	if (command_type == CMD_PASS) { // error msg already got sent, user doesn't need another one
		return -1;
	} else if (command_type == CMD_ERROR) {
		send_conn_response(ERR_COMMAND_INVALID, conn, ":Invalid command!\n");
		return -1;
	}

	token_t args[MAX_TOKS] = {0};
	for (int i = 2; i < toks_len; i++) {
		args[i - 2] = toks[i];
	}
	int args_found = toks_len - 2;

	// Command Dispatch
	switch (command_type) {
		case CMD_REGISTER: {
			if (args_found != 3) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Invalid number of args!\n");
				return -1;
			}

			char reg_token[MAX_B64_REG_TOK + 1] = {0};
			if (args[0].size > MAX_B64_REG_TOK) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Registration Token too long!\n");
				return -1;
			}
			memcpy(reg_token, args[0].ptr, args[0].size);

			char username[MAX_REFNAME + 1] = {0};
			if (args[1].size > MAX_REFNAME) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Username too long!\n");
				return -1;
			}
			memcpy(username, args[1].ptr, args[1].size);

			char password[MAX_PASSWORD + 1] = {0};
			if (args[2].size > MAX_PASSWORD) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Password too long!\n");
				return -1;
			}
			memcpy(password, args[2].ptr, args[2].size);

			user_t user = register_new_user(conn->db, reg_token, username, password);
			if (!user.id) {
				send_conn_response(ERR_AUTH_INVALID, conn, ":Credentials invalid\n");
				return -1;
			}

			// clear the tail of the conn username field so we don't have user leftovers
			memset(conn->name + args[1].size, 0, MAX_REFNAME - args[1].size);
			memcpy(conn->name, username, args[1].size);
			conn->id = user.id;
			conn->is_admin = user.is_admin;

			char *auth_token = generate_auth_token(engine->hkey, user.id, user.is_admin);

			printf("User %d (admin: %d) logged in with socket %d @ %s\n", conn->id, conn->is_admin, conn->sd, conn->addr);
			char tmp1[MAX_OUT_BUFFER] = {0};
			sprintf(tmp1, "\\register :%s\n", auth_token);
			free(auth_token);
			send_conn_response(0, conn, tmp1);

			char tmp2[MAX_OUT_BUFFER] = {0};
			sprintf(tmp2, "\\live\n");

			pthread_mutex_lock(&engine->conn_lock);
			for (int i = 0; i < MAX_CONNS; i++) {
				if (engine->conns[i].id != -1 && engine->conns[i].id != conn->id) {
					send_targeted_conn_response(0, &engine->conns[i], conn->name, tmp2);
				}
			}
			pthread_mutex_unlock(&engine->conn_lock);
		} break;
		case CMD_LOGIN: {
			if (args_found != 2) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Invalid number of args!\n");
				return -1;
			}

			char username[MAX_REFNAME + 1] = {0};
			if (args[0].size > MAX_REFNAME) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Username too long!\n");
				return -1;
			}
			memcpy(username, args[0].ptr, args[0].size);

			char password[MAX_PASSWORD + 1] = {0};
			if (args[1].size > MAX_PASSWORD) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Password too long!\n");
				return -1;
			}
			memcpy(password, args[1].ptr, args[1].size);

			user_t user = validate_auth(conn->db, username, password);
			if (!user.id) {
				send_conn_response(ERR_AUTH_INVALID, conn, ":Credentials invalid\n");
				return -1;
			}

			memset(conn->name + args[0].size, 0, MAX_REFNAME - args[0].size);
			memcpy(conn->name, username, args[0].size);
			conn->id = user.id;
			conn->is_admin = user.is_admin;

			char *auth_token = generate_auth_token(engine->hkey, user.id, user.is_admin);

			printf("User %d (admin: %d) logged in with socket %d @ %s\n", conn->id, conn->is_admin, conn->sd, conn->addr);
			char tmp1[MAX_OUT_BUFFER] = {0};
			sprintf(tmp1, "\\login :%s\n", auth_token);
			free(auth_token);

			send_conn_response(0, conn, tmp1);

			char tmp2[MAX_OUT_BUFFER] = {0};
			sprintf(tmp2, "\\live\n");

			pthread_mutex_lock(&engine->conn_lock);
			for (int i = 0; i < MAX_CONNS; i++) {
				if (engine->conns[i].id != -1 && engine->conns[i].id != conn->id) {
					send_targeted_conn_response(0, &engine->conns[i], conn->name, tmp2);
				}
			}
			pthread_mutex_unlock(&engine->conn_lock);
		} break;
		case CMD_CHANNELS: { return cmd_channels(engine, conn, args_found); } break;
		case CMD_LIVECHECK: { return cmd_livecheck(engine, conn, args_found); } break;
		case CMD_LEAVE: {
			if (args_found != 1) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":incorrect number of args\n");
				return -1;
			}

			if (args[0].ptr[0] != '#') {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Channels start with #\n");
				return -1;
			}

			// Grab channel name, chop off #
			char channelname[MAX_REFNAME + 1] = {0};
			if (args[0].size - 1 > MAX_REFNAME) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Channel name is too long\n");
				return -1;
			}
			memcpy(channelname, args[0].ptr + 1, args[0].size - 1);

			int channel_id = get_channel_id(conn->db, channelname);
			if (!channel_id) {
				send_conn_response(ERR_TARGET_INVALID, conn, ":channel not found\n");
				return -1;
			}

			if (!leave_channel(conn->db, conn->id, channel_id)) {
				send_conn_response(ERR_CHANNEL_INVALID, conn, ":Already in channel?\n");
				return -1;
			}

			printf("%s left %.*s\n", conn->name, args[0].size, args[0].ptr);

			char tmp[MAX_OUT_BUFFER] = {0};
			sprintf(tmp, "\\leave %.*s\n", args[0].size, args[0].ptr);

			int *user_list = get_users_in_channel(conn->db, channel_id);
			for (int i = 0; i < MAX_CHANNELS; i++) {
				if (!user_list[i]) {
					break;
				}

				pthread_mutex_lock(&engine->conn_lock);
				for (int j = 0; j < MAX_CONNS; j++) {
					if (engine->conns[j].id == user_list[i]) {
						send_targeted_conn_response(0, &engine->conns[j], conn->name, tmp);
					}
				}
				pthread_mutex_unlock(&engine->conn_lock);

			}

			// We're not in the channel list anymore, send this one manually
			send_targeted_conn_response(0, conn, conn->name, tmp);
		} break;
		case CMD_JOIN: {
			if (args_found != 1) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":incorrect number of args\n");
				return -1;
			}

			if (args[0].ptr[0] != '#') {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Channels start with #\n");
				return -1;
			}

			// Grab channel name, chop off #
			char channelname[MAX_REFNAME + 1] = {0};
			if (args[0].size - 1 > MAX_REFNAME) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Channel name is too long\n");
				return -1;
			}
			memcpy(channelname, args[0].ptr + 1, args[0].size - 1);

			int channel_id = get_channel_id(conn->db, channelname);
			if (!channel_id) {
				send_conn_response(ERR_TARGET_INVALID, conn, ":channel not found\n");
				return -1;
			}

			int num_users = get_channel_usercount(conn->db, channel_id);
			if (num_users >= MAX_CHANNEL_USERS) {
				send_conn_response(ERR_CHANNEL_FULL, conn, ":Channel is full\n");
				return -1;
			}

			if (!join_channel(conn->db, conn->id, channel_id)) {
				send_conn_response(ERR_CHANNEL_INVALID, conn, ":Already in channel?\n");
				return -1;
			}

			printf("%s joined %.*s\n", conn->name, args[0].size, args[0].ptr);

			char tmp[MAX_OUT_BUFFER] = {0};
			sprintf(tmp, "\\join %.*s\n", args[0].size, args[0].ptr);

			int *user_list = get_users_in_channel(conn->db, channel_id);
			for (int i = 0; i < MAX_CHANNELS; i++) {
				if (!user_list[i]) {
					break;
				}

				pthread_mutex_lock(&engine->conn_lock);
				for (int j = 0; j < MAX_CONNS; j++) {
					if (engine->conns[j].id == user_list[i]) {
						send_targeted_conn_response(0, &engine->conns[j], conn->name, tmp);
					}
				}
				pthread_mutex_unlock(&engine->conn_lock);

			}
		} break;
		case CMD_MSG: {
			if (args_found != 2) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Invalid msg: incorrect number of args\n");
				return -1;
			}

			char targetname[MAX_REFNAME + 1] = {0};
			if (args[0].size > MAX_REFNAME) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":Target name is too long\n");
				return -1;
			}
			memcpy(targetname, args[0].ptr, args[0].size);

			token_t msg = args[1];
			if (msg.size > MAX_MESSAGE_LEN) {
				send_conn_response(ERR_DATA_INVALID, conn, ":Message is too big!\n");
				return -1;
			}

			bool has_content = false;
			for (int i = 0; i < msg.size; i++) {
				if (!isspace(msg.ptr[i])) {
					has_content = true;
					break;
				}
			}

			if (!has_content) {
				send_conn_response(ERR_DATA_INVALID, conn, ":You sent an empty message!\n");
				return -1;
			}

			// Is it a channel?
			if (targetname[0] == '#') {
				int channel_id = get_channel_id(conn->db, targetname + 1);
				if (!channel_id) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":channel not found\n");
					return -1;
				}

				bool found_me = check_user_in_channel(conn->db, conn->id, channel_id);
				if (!found_me) {
					send_conn_response(ERR_CHANNEL_INVALID, conn, ":You can't send messages to channels you haven't joined\n");
					return -1;
				}

				printf("Storing %s message in history\n", targetname);
				uint64_t msg_id = store_channel_message(conn->db, channel_id, conn->id, args[1].ptr, args[1].size);

				char tmp[MAX_OUT_BUFFER] = {0};
				sprintf(tmp, "\\msg %lu %s :%.*s\n", (unsigned long)msg_id, targetname, args[1].size, args[1].ptr);

				int *user_list = get_users_in_channel(conn->db, channel_id);
				for (int i = 0; i < MAX_CHANNELS; i++) {
					if (!user_list[i]) {
						break;
					}

					pthread_mutex_lock(&engine->conn_lock);
					for (int j = 0; j < MAX_CONNS; j++) {
						if (engine->conns[j].id == user_list[i]) {
							send_targeted_conn_response(0, &engine->conns[j], conn->name, tmp);
						}
					}
					pthread_mutex_unlock(&engine->conn_lock);

				}

				free(user_list);
				return 0;

			// Is it a user?
			} else {
				int target_user = get_user_id(conn->db, targetname);
				if (!target_user) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":user not found\n");
					return -1;
				}

				if (conn->id == target_user) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":Can't sent to yourself!\n");
					return -1;
				}

				// This needs to be atomic. If I ever go threaded, this approach *sucks*
				pm_channel_t pm_chan = get_pm_channel(conn->db, conn->id, target_user);
				if (!pm_chan.id) {
					pm_chan.id = add_pm_channel(conn->db, conn->id, target_user);
					if (pm_chan.id == 0) {
						panic("Failed to create new pm channel!\n");
					}

					pm_chan.user1 = conn->id;
					pm_chan.user2 = target_user;
				}

				bool to_user2 = false;
				if (pm_chan.user2 == target_user) {
					to_user2 = true;
				}

				printf("Storing %s -> %s PM in history\n", conn->name, targetname);
				uint64_t msg_id = store_pm(conn->db, pm_chan.id, to_user2, args[1].ptr, args[1].size);

				char tmp[MAX_OUT_BUFFER] = {0};
				sprintf(tmp, "\\msg %lu %s :%.*s\n", (unsigned long)msg_id, targetname, args[1].size, args[1].ptr);
				send_targeted_conn_response(0, conn, conn->name, tmp);

				conn_t *other_conn = NULL;

				pthread_mutex_lock(&engine->conn_lock);
				for (int i = 0; i < MAX_CONNS; i++) {
					if (target_user == engine->conns[i].id) {
						other_conn = &engine->conns[i];
						break;
					}
				}
				pthread_mutex_unlock(&engine->conn_lock);

				if (other_conn) {
					send_targeted_conn_response(0, other_conn, conn->name, tmp);
				}

				return 0;
			}

			send_conn_response(ERR_TARGET_INVALID, conn, ":target not found, delivery failed\n");
		} break;
		case CMD_USERS: { return cmd_users(engine, conn, args_found); } break;
		case CMD_CHANNELUSERS: {
			if (args_found != 1) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":incorrect number of args\n");
				return -1;
			}

			if (args[0].ptr[0] != '#') {
				send_conn_response(ERR_TARGET_INVALID, conn, ":channels must start with #\n");
				return -1;
			}

			// Grab channel name, chop off #
			char channelname[MAX_REFNAME + 1] = {0};
			if (args[0].size - 1 > MAX_REFNAME) {
				send_conn_response(ERR_TARGET_INVALID, conn, ":channelname too long\n");
				return -1;
			}
			memcpy(channelname, args[0].ptr + 1, args[0].size - 1);

			int channel_id = get_channel_id(conn->db, channelname);
			if (!channel_id) {
				send_conn_response(ERR_TARGET_INVALID, conn, ":channel not found\n");
				return -1;
			}

			char **user_list = get_usernames_in_channel(conn->db, channel_id);

			// space for comma separated channels ex: #fee, #fi, #fo, #fum
			char users_str[(MAX_CHANNEL_USERS * MAX_REFNAME) + (MAX_CHANNEL_USERS * 2)] = {0};
			int plop_iter = 0;
			for (int i = 0; i < MAX_CHANNEL_USERS; i++) {
				if (!user_list[i]) {
					break;
				}

				char *fmtstr = "%s, ";
				if (i + 1 >= MAX_CHANNEL_USERS || !user_list[i + 1]) {
					fmtstr = "%s";
				}

				plop_iter += sprintf(users_str + plop_iter, fmtstr, user_list[i]);
				free(user_list[i]);
			}
			free(user_list);

			char tmp[MAX_OUT_BUFFER] = {0};
			sprintf(tmp, "\\channelusers #%s :%s\n", channelname, users_str);
			send_conn_response(0, conn, tmp);
		} break;
		case CMD_TIME: {
			char tmp[MAX_OUT_BUFFER] = {0};
			char curtime[80];
			char boottime[80];

			time_t now = time(NULL);
			struct tm *nowts = localtime(&now);
			strftime(curtime, sizeof(curtime), "%a %Y-%m-%d %H:%M:%S %Z", nowts);
			struct tm *bootts = localtime(&engine->boot_time);
			strftime(boottime, sizeof(boottime), "%a %Y-%m-%d %H:%M:%S %Z", bootts);

			sprintf(tmp, "\\time :cur: %s; boot: %s\n", curtime, boottime);
			send_conn_response(0, conn, tmp);
		} break;
		case CMD_YEET: {
			conn->heartbeat_started = false;
			send_conn_response(0, conn, ":yeet success\n");
		} break;
		case CMD_GENTOKEN: {
			char *token = gen_reg_token(conn->db, false);

			char tmp[MAX_OUT_BUFFER] = {0};
			sprintf(tmp, "\\gentoken :%s\n", token);
			free(token);

			send_conn_response(0, conn, tmp);
		} break;
		case CMD_HISTORY: {
			if (args_found != 1) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":incorrect number of args\n");
				return -1;
			}

			char targetname[MAX_REFNAME + 1] = {0};
			if (args[0].size > MAX_REFNAME) {
				send_conn_response(ERR_TARGET_INVALID, conn, ":target too long\n");
				return -1;
			}
			memcpy(targetname, args[0].ptr, args[0].size);

			// Is it a channel?
			if (targetname[0] == '#') {
				int channel_id = get_channel_id(conn->db, targetname + 1);
				if (!channel_id) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":channel not found\n");
					return -1;
				}

				bool found_me = check_user_in_channel(conn->db, conn->id, channel_id);
				if (!found_me) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":Channel not joined\n");
					return 0;
				}

				int total_size = get_total_cms(conn->db, channel_id);
				int chunk_size = 0;
				message_t *message_list = get_channel_history(conn->db, channel_id, 0, &chunk_size);

				char tmp[MAX_OUT_BUFFER] = {0};
				sprintf(tmp, "\\history %s :Sending chunk 0 %d %d\n", targetname, chunk_size, total_size);
				send_conn_response(0, conn, tmp);

				for (int i = chunk_size - 1; i >= 0; i--) {
					char tmp[MAX_OUT_BUFFER] = {0};
					sprintf(tmp, "0 %ld %s \\msg %lu %s :%.*s\n",
						message_list[i].created,
						message_list[i].sender, (unsigned long)message_list[i].id, targetname, message_list[i].len, message_list[i].data);
					send_conn_raw(conn, tmp);
				}

				free(message_list);

				return 0;

			// Is it a user?
			} else {
				int target_id = get_user_id(conn->db, targetname);
				if (!target_id) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":user not found\n");
					return -1;
				}

				if (target_id == conn->id) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":Can't get history for self\n");
					return -1;
				}

				pm_channel_t pm_chan = get_pm_channel(conn->db, conn->id, target_id);
				if (!pm_chan.id) { // No history exists for this user
					char tmp[MAX_OUT_BUFFER] = {0};
					sprintf(tmp, "\\history %s :Sending chunk 0 0 0\n", targetname);
					send_conn_response(0, conn, tmp);
					return 0;
				}

				int total_size = get_total_pms(conn->db, pm_chan.id);
				int chunk_size = 0;
				message_t *message_list = get_pm_history(conn->db, pm_chan.id, 0, &chunk_size);

				char tmp[MAX_OUT_BUFFER] = {0};
				sprintf(tmp, "\\history %s :Sending chunk 0 %d %d\n", targetname, chunk_size, total_size);
				send_conn_response(0, conn, tmp);

				for (int i = chunk_size - 1; i >= 0; i--) {
					char tmp[MAX_OUT_BUFFER] = {0};
					sprintf(tmp, "0 %ld %s \\msg %lu %s :%.*s\n",
						message_list[i].created,
						message_list[i].sender, (unsigned long)message_list[i].id, message_list[i].target, message_list[i].len, message_list[i].data);
					send_conn_raw(conn, tmp);
				}

				free(message_list);
				return 0;
			}
		} break;
		case CMD_MYCHANNELS: {
			if (args_found != 0) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":incorrect number of args\n");
				return -1;
			}

			msg_read_t *channel_list = get_channel_unread_list(conn->db, conn->id);

			// ex: (#fee, 0), (#fi, 1), (#fo, 2), (#fum, 0)
			// channelstr size + space/parens/comma size + number size
			char channel_str[(MAX_CHANNELS * MAX_REFNAME) + (MAX_CHANNELS * 6) + (MAX_CHANNELS * 8)] = {0};
			int plop_iter = 0;
			for (int i = 0; i < MAX_CHANNELS; i++) {
				if (!channel_list[i].name[0]) {
					break;
				}

				char *fmtstr = "(#%s, %d), ";
				if (i + 1 >= MAX_CHANNELS || !channel_list[i + 1].name[0]) {
					fmtstr = "(#%s, %d)";
				}

				plop_iter += sprintf(channel_str + plop_iter, fmtstr, channel_list[i].name, channel_list[i].unread);
			}
			free(channel_list);

			char tmp[MAX_OUT_BUFFER] = {0};
			sprintf(tmp, "\\mychannels :%s\n", channel_str);
			send_conn_response(0, conn, tmp);

			return 0;
		} break;
		case CMD_MYPMS: {
			if (args_found != 0) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":incorrect number of args\n");
				return -1;
			}

			msg_read_t *user_list = get_pm_unread_list(conn->db, conn->id);

			// ex: (fee, 0), (fi, 1), (fo, 2), (fum, 0)
			// userstr size + space/parens/comma size + number size
			char users_str[(MAX_USERS * MAX_REFNAME) + (MAX_USERS * 6) + (MAX_USERS * 8)] = {0};
			int plop_iter = 0;
			for (int i = 0; i < MAX_USERS; i++) {
				if (!user_list[i].name[0]) {
					break;
				}

				char *fmtstr = "(%s, %d), ";
				if (i + 1 >= MAX_USERS || !user_list[i + 1].name[0]) {
					fmtstr = "(%s, %d)";
				}

				plop_iter += sprintf(users_str + plop_iter, fmtstr, user_list[i].name, user_list[i].unread);
			}
			free(user_list);

			char tmp[MAX_OUT_BUFFER] = {0};
			sprintf(tmp, "\\mypms :%s\n", users_str);
			send_conn_response(0, conn, tmp);

			return 0;
		} break;
		case CMD_COUNTUNREAD: {
			if (args_found != 1) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":incorrect number of args\n");
				return -1;
			}

			char targetname[MAX_REFNAME + 1] = {0};
			if (args[0].size > MAX_REFNAME) {
				send_conn_response(ERR_TARGET_INVALID, conn, ":target too long\n");
				return -1;
			}
			memcpy(targetname, args[0].ptr, args[0].size);

			// Is it a channel?
			if (targetname[0] == '#') {
				int channel_id = get_channel_id(conn->db, targetname + 1);
				if (!channel_id) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":channel not found\n");
					return -1;
				}

				bool found_me = check_user_in_channel(conn->db, conn->id, channel_id);
				if (!found_me) {
					char tmp[MAX_OUT_BUFFER] = {0};
					sprintf(tmp, "\\countunread %s 0\n", targetname);
					send_conn_response(0, conn, tmp);
					return 0;
				}

				int unread_count = get_total_unread_cms(conn->db, channel_id, conn->id);
				if (!unread_count) {
					char tmp[MAX_OUT_BUFFER] = {0};
					sprintf(tmp, "\\countunread %s 0\n", targetname);
					send_conn_response(0, conn, tmp);
					return 0;
				}

				char tmp[MAX_OUT_BUFFER] = {0};
				sprintf(tmp, "\\countunread %s %d\n", targetname, unread_count);
				send_conn_response(0, conn, tmp);
				return 0;

			// Is it a user?
			} else {
				int target_user = get_user_id(conn->db, targetname);
				if (!target_user) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":user not found\n");
					return -1;
				}

				if (conn->id == target_user) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":wat. does not compute\n");
					return -1;
				}

				pm_channel_t pm_chan = get_pm_channel(conn->db, conn->id, target_user);
				if (!pm_chan.id) {
					char tmp[MAX_OUT_BUFFER] = {0};
					sprintf(tmp, "\\countunread %s 0\n", targetname);
					send_conn_response(0, conn, tmp);
					return 0;
				}

				bool is_user1 = false;
				if (pm_chan.user1 == conn->id) {
					is_user1 = true;
				}

				int unread_count = get_total_unread_pms(conn->db, pm_chan.id, is_user1);
				if (!unread_count) {
					char tmp[MAX_OUT_BUFFER] = {0};
					sprintf(tmp, "\\countunread %s 0\n", targetname);
					send_conn_response(0, conn, tmp);
					return 0;
				}

				char tmp[MAX_OUT_BUFFER] = {0};
				sprintf(tmp, "\\countunread %s %d\n", targetname, unread_count);
				send_conn_response(0, conn, tmp);
				return 0;
			}
		} break;
		case CMD_MARKREAD: {
			if (args_found != 1) {
				send_conn_response(ERR_ARGS_INVALID, conn, ":incorrect number of args\n");
				return -1;
			}

			char targetname[MAX_REFNAME + 1] = {0};
			if (args[0].size > MAX_REFNAME) {
				send_conn_response(ERR_TARGET_INVALID, conn, ":target too long\n");
				return -1;
			}
			memcpy(targetname, args[0].ptr, args[0].size);

			// Is it a channel?
			if (targetname[0] == '#') {
				int channel_id = get_channel_id(conn->db, targetname + 1);
				if (!channel_id) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":channel not found\n");
					return -1;
				}

				bool found_me = check_user_in_channel(conn->db, channel_id, conn->id);
				if (!found_me) {
					send_conn_response(0, conn, ":no unread messages\n");
					return 0;
				}

				channel_mark_read(conn->db, channel_id, conn->id);

				char tmp[MAX_OUT_BUFFER] = {0};
				sprintf(tmp, "\\markread %s\n", targetname);
				send_conn_response(0, conn, tmp);
				return 0;

			// Is it a user?
			} else {
				int target_user = get_user_id(conn->db, targetname);
				if (!target_user) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":user not found\n");
					return -1;
				}

				if (conn->id == target_user) {
					send_conn_response(ERR_TARGET_INVALID, conn, ":wat. does not compute\n");
					return -1;
				}

				pm_channel_t pm_chan = get_pm_channel(conn->db, conn->id, target_user);
				if (!pm_chan.id) {
					send_conn_response(0, conn, ":\\markread %s\n");
					return 0;
				}

				bool is_user1 = false;
				if (pm_chan.user1 == conn->id) {
					is_user1 = true;
				}

				pm_channel_mark_read(conn->db, pm_chan.id, is_user1);

				char tmp[MAX_OUT_BUFFER] = {0};
				sprintf(tmp, "\\markread %s\n", targetname);
				send_conn_response(0, conn, tmp);
				return 0;
			}
		} break;
		default: {
			send_conn_response(ERR_COMMAND_INVALID, conn, ":Invalid command!\n");
			return -1;
		} break;
	}

	return 0;
}
