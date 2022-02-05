set -euox pipefail

clang -O3 -g -o snowfort -pthread -lsqlite3 -lssl -lcrypto -I /usr/local/opt/openssl/include -L /usr/local/opt/openssl/lib src/server/server.c src/server/commands.c src/server/db.c src/server/comms.c
clang -O3 -g -o iceball -lncurses -lssl -lcrypto -I /usr/local/opt/openssl/include -L /usr/local/opt/openssl/lib src/client/client.c src/client/comms.c
