## Charrua DHCP - a DHCP client, server and wire frame encoder and decoder


[![docs](https://img.shields.io/badge/doc-online-blue.svg)](http://mirage.github.io/charrua-dhcp/api)
[![Build Status](https://travis-ci.org/mirage/charrua-core.svg)](https://travis-ci.org/mirage/charrua-dhcp)

[charrua](http://www.github.com/mirage/charrua-dhcp) is an
_ISC-licensed_ DHCP library implementation in OCaml.
It provides three packages:

- charrua-core: a library that handles wire traffic parsing and a server implementation
- charrua-client: a client library, with a portable version and one using the MirageOS interfaces
- charrua-unix: a Unix DHCP server implementation

### Charrua-core

Charrua-core consists of two modules, a `Dhcp_wire` responsible for parsing and
constructing DHCP messages and a `Dhcp_server` module used for constructing DHCP
servers.

You can browse the API for [charrua-core](http://www.github.com/mirage/charrua-core) at
http://mirage.github.io/charrua-core/api

[mirage](https://github.com/mirage/mirage-skeleton/tree/master/applications/dhcp)
is a Mirage DHCP unikernel server based on charrua-core.

#### Features

* `Dhcp_server` supports a stripped down ISC dhcpd.conf, so you can probably just
  use your old `dhcpd.conf`, it also supports manual configuration building in
  OCaml.
* Logic/sequencing is agnostic of IO and platform, so it can run on Unix as a
  process, as a Mirage unikernel or anything else.
* `Dhcp_wire` provides marshalling and unmarshalling utilities for DHCP, it is the
  base for `Dhcp_server`.
* All DHCP options are supported at the time of this writing.
* Code is purely applicative.
* It's in OCaml, so it's pretty cool.

The name `charrua` is a reference to the, now extinct, semi-nomadic people of
southern South America.

### Charrua-client

charrua-client is a DHCP client powered by [charrua-core](https://github.com/haesbaert/charrua-core).

The base library exposes a simple state machine for acquiring a DHCP lease.

A sublibrary, `charrua-client.mirage`, exposes an additional functor for use
with the [MirageOS library operating system](https://github.com/mirage/mirage).

### Charrua-unix Server

charrua-unix is an _ISC-licensed_ Unix DHCP daemon based on
[charrua-dhcp](http://www.github.com/mirage/charrua-dhcp).

#### Features

* Supports a stripped down ISC dhcpd.conf. A configuration sample can be found
[here](https://github.com/haesbaert/charrua-core/blob/master/sample/dhcpd.conf)
* Priviledge dropping, the daemon doesn't run as root.
* Almost purely-functional code.
* Support for multiple interfaces/subnets.

Try `charruad --help` for options.

This project became one of the [Mirage Pioneer](https://github.com/mirage/mirage-www/wiki/Pioneer-Projects)
projects.
