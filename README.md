# Snowfort

Snowfort is an IRC-like server and example client (iceball), with support for UTF-8, 
accounts, user permissions, and history

![Iceball Demo](/media/iceball.gif)

Snowfort is *not* production ready, it's an interesting demo. 
It needs more work before a real deployment, like a better password hashing algorithm
and some heavy load testing

## Setup

On first boot of snowfort, the server will produce a registration token,
valid for 1 hour, to use to create an admin account. The admin account can then issue
both user and admin tokens using `\gentoken` so users can create their own accounts.
Note, the system doesn't differentiate between server head, and any other admin,
any system admin can remove any other system admin.

## Protocol Documentation

The server protocol is documented in the included [RFC](rfc.md). The documentation may be
slightly out of date, the protocol is still in need of a cleanup pass to make calls more
uniform.
