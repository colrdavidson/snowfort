# Chat Client RFC

## snowfort (server)
The server is set up to use TCP over IPv4 and IPv6 (whichever the client prefers).
Default port is 9253

## iceball (client)
A TCP over IPv4 and IPv6 example client

## Basic Usage
The first thing the client MUST do is send a `\login <name>` message, which configures screen name
Second, the client might want to run `\channels` to get a comma separated list of channels,
and then `\join <#channel>` to join one that sounds neat
To send a message, `\msg <name>/<#channel> :Your message`.

## General Message Formatting
Every message must fit within (1024 -- subject to change) UTF-8 codepoints,
with an `\n` as the terminal character, `\n` included in char count

` ` is used as a token separator
`:` at the beginning of a sequence is used to denote a string. Everything beyond that point will ignore ` ` token separators until the next `\n`
`\` before the beginning `:` prevents reading the sequence as a string. This is typically used so the server can send IPv6 addresses without breaking the rest of the message

A message `01234 \:0:1:2:3 :foobar is delicious` should be parsed into three tokens:
`01234`, `:0:1:2:3`, and `foobar is delicious`


## Client Message Format
Client messages should use the format `<auth_token> <command> <args>\n`

- Before logging in, all clients should send a "0" in the auth token slot.
- On successful login or registration, clients recieve an auth token string
- After logging in, if the connection remains alive, clients may continue to send "0".
- If on a REST bridge, or if the client wishes to resume without resending credentials (resuming through flaky connections?),
clients may send the auth token they recieved to reestablish authorization
- After some period of non-use, the session may time out and the client will be required to re-log to aquire a fresh token


## Response Format
Server responses will come for most commands/errors, and use the format `<status> <time> <sendername> <cmd> <msg>`
time is seconds from unix epoch

Ex: `\channels` -> `0 1623486335 jeff \channels :#eng-root, #offtopic`
- (0: success, jeff: username, msg)
- (server responded with channel list)

Ex: `\msg #eng-root :Hello World` -> `0 1623486335 jeff \msg #eng-root :Hello World`
- (0: success, jeff: username, msg)
- (jeff sent Hello World to #eng-root)

Ex: `\msg #invalid-channel 3` -> `1 1623486335 jeff :You Failed`
- (1: error, jeff: username, msg)
- (server rejected your broken msg)


## Supported Commands

### Auth Commands
After a successful auth, the server will also send a response for `\users`, `\channels`, `\mypms`, and `\mychannels` to reduce client spin-up roundtrips

#### login
Login grants your connection permissions and returns you an auth token
`\login <username> <password>`

Ex: `\login xXThirstMutilatorXx chugchugchug` -> `0 1623486335 xXThirstMutilatorXx \login :<auth_token>`

#### register
Register creates a user account and returns you an auth token
`\register <registration_token> <username> <password>`

Registration tokens used here are single use and have expiry dates, so don't be a slowpoke
Ex: `\register <registration_token> I'mABigBeefyBoy actuallynottho` -> `0 1623486335 I'mABigBeefyBoy \register :<auth_token>`


### General Comms Commands
#### msg
msg sends to a user directly, or to a channel, which gets broadcasted to everyone in that channel
`\msg <name>/<#channel>/<userid> :message`

Ex: `\msg #eng-root :I like pizza` -- Sends "I like pizza" to #eng-root
Ex: `\msg squidward :Is mayonnaise an instrument?` -- Sends "Is mayonnaise an instrument?" to squidward

#### channels
Returns the list of all accessible channels as a comma separated list, and takes no arguments
`\channels`
Ex: `\channels` -> `0 1623486335 jeff \channels :#eng-root, #offtopic, #💩`

#### mychannels
Returns the list of all channels the client user is part of as a comma separated list, and takes no arguments
`\mychannels`
Ex: `\mychannels` -> `0 1623486335 jeff \mychannels :#eng-root, #💩`

#### mypms
Returns the list of all users the client user has pm'd is part of as a comma separated list, and takes no arguments
`\mypms`
Ex: `\mypms` -> `0 1623486335 jeff \mypms :squidward, picard`

#### join
Takes the name of the channel you wish to join, and adds you to the list of recipients for messages targeted at that channel
`\join <channel>`

Ex: `\join #eng-root` -- joins #eng-root

#### leave
Removes you from a channel
`\leave <channel>`

Ex: `\leave #eng-root` -- leaves #eng-root

#### users
Returns the list of all users in a channel (as user ids) as a comma separated list
`\users <channel>`

Ex: `\users #eng-root` -> `0 1623486335 jeff \users #eng-root :squidward, Cats_Are_🔥, picard`


### History Commands
These are all paginated, returning a batch of up to (50 -- subject to change) at a time.
When queried, the page index argument is optional, and the first response message contains:
`<current page> <page size> <total page count>`

#### history
Gets the history for the target (channel or username), newest to oldest, with the most recent message last in the message batch
`\history <channel/username> [page idx]`

Ex: `\history #catfacts` ->
`0 1623486335 jeff \channelhistory #catfacts 1 2 100`
`0 1623486335 jeff \msg #catfacts :Cats are actually non-newtonian fluids`
`0 1623486338 butter-aint-real \msg #catfacts :Hmm... I dunno`

Ex: `\pmhistory picard 2` ->
`0 1623486335 jeff \pmhistory picard 2 2 20`
`0 1623486335 jeff \msg picard :Which enterprise had the detachable bits?`
`0 1623486338 picard \msg jeff :All of them technically, assuming you shot at them enough`



### Utility Commands
#### time
Gets the server current time and the server boot time; Time string format not yet defined
`\time`

Ex: `\time` -> `0 1623486335 jeff \time :cur: blah blah blah; boot: blah blah blah`

#### yeet
When the server sends `\toss`, respond `\yeet` ASAP.
Client should be able to do the same to the server to ensure the server isn't dead

a successful yeet returns:
`0 1623486335 jeff \yeet :success`



### Admin Commands
None of these exist yet, but are probably worth having

#### create-channel
`\create-channel public #phyllotaxy-is-boring`
`\create-channel private #galaxy-brains-love-plants`

#### delete-channel
`\delete-channel #my-cactus-is-expired`

#### delete-user
`\delete-user don'tdeletemebro`

#### reboot-server
`\reboot-server`

#### add-to-channel
Add user to a private channel
`\add-to-channel #nobody-here-but-us-chickens`

#### remove-from-channel
Remove user from a private channel
`\remove-from-channel #this-is-supposed-to-be-empty`

#### make-admin
`\make-admin thedude`

#### unmake-admin
`\unmake-admin terribleop`

#### vaporize-lemmings
Does what it says on the tin. Did you actually read this far?
