set -euox pipefail

clang -O3 -g -o snowfort -pthread -lsqlite3 -lssl -lcrypto src/server/server.c src/server/commands.c src/server/db.c src/server/comms.c
clang -O3 -g -o iceball -lncursesw -lssl -lcrypto src/client/client.c src/client/comms.c
