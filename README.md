## Charrua DHCP - a DHCP client, server and wire frame encoder and decoder


[![docs](https://img.shields.io/badge/doc-online-blue.svg)](https://mirage.github.io/charrua/)
[![Build Status](https://travis-ci.org/mirage/charrua.svg)](https://travis-ci.org/mirage/charrua)

[charrua](http://www.github.com/mirage/charrua) is an
_ISC-licensed_ DHCP library implementation in OCaml.
It provides five packages:

- charrua: a library that handles wire traffic parsing
- charrua-server: a DHCP server implementation
- charrua-client: a library for handling DHCP client state and messages
- charrua-client-lwt: a DHCP client library with timeouts and network read/write
- charrua-client-mirage: a MirageOS-compatible set of interfaces to charrua-client-lwt
- charrua-unix: a Unix DHCP server implementation

### Charrua

The name `charrua` is a reference to the, now extinct, semi-nomadic people of
southern South America.

Charrua consists of the single module `Dhcp_wire` responsible for parsing and
constructing DHCP messages,

You can browse the API for [charrua](https://www.github.com/mirage/charrua) at
https://mirage.github.io/charrua/

#### Features

* `Dhcp_wire` provides marshalling and unmarshalling utilities for DHCP, it is the
  base for `Dhcp_server`.
* Logic/sequencing is agnostic of IO and platform, so it can run on Unix as a
  process, as a Mirage unikernel or anything else.
* All DHCP options are supported at the time of this writing.
* Code is purely applicative.
* It's in OCaml, so it's pretty cool.

### Charrua-server

The module `Dhcp_server` supports a stripped down ISC `dhcpd.conf`, so you can
probably just use your old `dhcpd.conf`. It also supports manual configuration
building in OCaml.

[dhcp](https://github.com/mirage/mirage-skeleton/tree/master/applications/dhcp)
is a [MirageOS](https://mirage.io) DHCP unikernel server based on charrua,
included as a part of the MirageOS unikernel example and starting-point
repository.

### Charrua-client

charrua-client is a DHCP client powered by [charrua](https://github.com/mirage/charrua).

The base library exposes a simple state machine in `Dhcp_client`
for use in acquiring a DHCP lease.

`charrua-client-lwt` extends `charrua-client` with a functor `Dhcp_client_lwt`,
using the provided modules for timing and networking logic,
for convenient use by a program which might wish to implement a full client.

`charrua-client-mirage` exposes an additional `Dhcp_client_mirage` for direct use
with the [MirageOS library operating system](https://github.com/mirage/mirage).

### Charrua-unix Server

charrua-unix is an _ISC-licensed_ Unix DHCP daemon based on
[charrua](http://www.github.com/mirage/charrua).

#### Features

* Supports a stripped down ISC dhcpd.conf. A configuration sample can be found
[here](https://github.com/mirage/charrua/blob/master/sample/dhcpd.conf)
* Privilege dropping: the daemon doesn't run as root.
* Almost purely-functional code.
* Support for multiple interfaces/subnets.

Try `charruad --help` for options.

This project became one of the [Mirage Pioneer](https://github.com/mirage/mirage-www/wiki/Pioneer-Projects)
projects.
