## Charrua DHCP core library - a DHCP server and wire frame encoder and decoder

[charrua-core](http://www.github.com/mirage/charrua-core) is an
_ISC-licensed_ DHCP library implementation in OCaml.

[![docs](https://img.shields.io/badge/doc-online-blue.svg)](http://mirage.github.io/charrua-core/api)
[![Build Status](https://travis-ci.org/mirage/charrua-core.svg)](https://travis-ci.org/mirage/charrua-core)

It provides basically two modules, a `Dhcp_wire` responsible for parsing and
constructing DHCP messages and a `Dhcp_server` module used for constructing DHCP
servers.

[charrua-unix](http://www.github.com/haesbaert/charrua-unix) is a Unix DHCP
server based on charrua-core.

[mirage](https://github.com/mirage/mirage-skeleton/tree/master/applications/dhcp)
is a Mirage DHCP unikernel server based on charrua-core.

You can browse the API for [charrua-core](http://www.github.com/mirage/charrua-core) at
http://mirage.github.io/charrua-core/api

### Charrua-client

charrua-client is a DHCP client powered by [charrua-core](https://github.com/haesbaert/charrua-core).

The base library exposes a simple state machine for acquiring a DHCP lease.

An optional sublibrary, `charrua-client.mirage`, exposes an additional functor for use with the [MirageOS library operating system](https://github.com/mirage/mirage).

#### Features

* Dhcp_server supports a stripped down ISC dhcpd.conf, so you can probably just
  use your old dhcpd.conf, it also supports manual configuration building in
  ocaml.
* Logic/sequencing is agnostic of IO and platform, so it can run on Unix as a
  process, as a Mirage unikernel or anything else.
* Dhcp_wire provides marshalling and unmarshalling utilities for DHCP, it is the
  base for Dhcp_server.
* All DHCP options are supported at the time of this writing.
* Code is purely applicative.
* It's in ocaml, so it's pretty cool.

The name `charrua` is a reference to the, now extinct, semi-nomadic people of
southern South America.

This project became one of the [Mirage Pioneer](https://github.com/mirage/mirage-www/wiki/Pioneer-Projects)
projects.
