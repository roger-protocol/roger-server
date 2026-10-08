# roger-server

`roger-server` is the official Go implementation repository of the [Roger Protocol](https://rogerprotocol.org).
It compiles into `rogerd`, a lightweight and self-hostable daemon that can be used by Roger compatible clients.

`rogerd` aims to be lightweight: it uses sqlite for the database and chi for the API routing
