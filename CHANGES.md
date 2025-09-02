### v2.1.0 (2025-09-02)

* Add support for client FQDN (RFC 4702) (#133 @hannesm)
* Client: allow cidr, gateway, no_init being passed to connect. If passed,
  no DHCP requests will be done. This enables MirageOS unikernels where the
  decision whether to do DHCP or not is done at runtime (#135 @hannesm)
* Client: pass options to be embedded in the DHCP request (#135 @hannesm)
* server: extend Update and Reply with lease and DHCP options (#135 @hannesm)

### v2.0.0 (2025-02-11)

* Adapt to tcpip 9.0.0 API changes (less functors) (#132 @hannesm)
* Adapt to mirage-crypto 1.2.0 API changes (#131 @hannesm)

### v1.6.0 (2024-12-09)

* charruad: update to new cmdliner (#117 @haesbaert)
* support mtime >= 2.0.0 (#121 @haesbaert, @tmcgilchrist)
* charrua-unix: use duration package (#122 @hannesm)
* replace Cstruct.copy by Cstruct.to_string (#123 @gridbugs)
* use mirage-crypto-rng instead of mirage-random-test (#126 @hannesm)
* remove mirage-random dependency, use mirage-crypto-rng instead - and update
  to mirage-crypto-rng >= 1.0.0 (#127 @hannesm)
* remove ppx_cstruct and sexplib from dependency cone (#128 @hannesm)
* charrua-client: update to tcpip >= 8.1.0 (#129 @hannesm)

### v1.5.0 (2021-12-15)

* Adapt to mirage-protocols 8.0.0, ethernet 3.0.0, arp 3.0.0, and tcpip 7.0.0
  changes (#116 @hannesm)
* Avoid deprecated Lwt_main.yield, use Lwt.pause instead (#115 @hannesm)

### v1.4.1 (2021-10-27)

* Add database serializers (db_of_string/db_to_string) #112 @haesbaert
* Remove rresult dependency (#114 @hannesm)
* Avoid deprecated Cstruct.len function

### v1.4.0 (2021-07-19)

Changes in #111 by @haesbaert

* Allow optional arguments to be erased in Dhcp_server.make
* maxleasetime -> max-lease-time in dhcpd.conf
* fix handling of DHCPRELEASE
* rewrite lease database
* charruad: collect garbage leases, write pid file, implement -u/--user and
  -g/--group
* opam lint, raise lower bound to 4.08.0

### v1.3.0 (2020-11-25)

* Revise packaging: charrua-client-lwt and charrua-client-mirage are now
  available as charrua-client.lwt and charrua-client.mirage (#110 @hannesm)
* Dhcp_ipv4 directly uses Dhcp_client_mirage (instead of an abstract module
  interface being passed) (#110 @hannesm)
* Fix sending of client_identifier with appropriate type as sent by the client
  (#98 @hannesm, reported in #84 by @lynxis)

### v1.2.2 (2020-06-22)

* Support for ipaddr 5.0.0 and tcpip 5.0.0 (#109 @hannesm)

### v1.2.1 (2020-05-11)

* Fix minimal dune version (1.4) (#108 @samoht)

### v1.2.0 (2019-11-01)

* adapt to mirage-protocols 4.0.0 and tcpip 4.0.0 changes (#105 @hannesm)
* bump lower bound to OCaml 4.06.0 (#105 @hannesm)

### v1.1.0 (2019-07-18)

* support ipaddr/macaddr.4.0.0 interfaces (#103 @avsm)
* cleanup warnings in dune's default dev profile (#103 @avsm)
* test with OCaml 4.08.0 (#103 @avsm)

### v1.0.0 (2019-04-18)

* explicit sexplib dependency, compatible with cstruct 4.0.0 (#99, @TheLortex)
* charrua-server is an independent opam package now (#100, @hannesm)
* charrua is the new name for charrua-core (#100, @hannesm)
* the repository moved to https://github.com/mirage/charrua

### v0.12.0 (2019-02-25)

* Adjust to mirage-net 2.0.0 and mirage-protocols 2.0.0 changes (#94, @hannesm)

### v0.11.2 (2019-02-05)

* build system ported to dune (#92, @hannesm)
* compatibility with tcpip 3.7.0 (#91, @hannesm)
* compatibility with rawlink 1.0 (#90, @hannesm)

### v0.11.1 (2019-01-09)

* compatibility with ipaddr 3.0 (#88, @hannesm)
* compatibility with tcpip 3.6.0 (#88, @hannesm)

### v0.11.0 (2018-11-16)

* client: use the Random interface from Mirage directly, avoid calls to Stdlibrandom (removed from mirage-random 1.2.0)
* unix: require lwt_log explicitly

### v0.10 (2018-09-16)

* charrua-unix: safe-string support (@haesbaert)
* client: add "anonymity profiles" by asking for common sets of options, to reduce the ease of profiling users by the set of DHCP requests sent (#76 @juga0)
* core, client: Document code using comments (#76 and #78, @juga0 @yomimono)
* core: add documentation and RFCs for specs we support (@juga0)
* unix: add support for 4.06.0 via Bytes.to_string in charruad.ml (@haesbaert)
* Support private_classless_static_route option (#76 @juga0)
* Adjust to tcpip 3.5.0 and mirage-protocols-lwt 1.4.0 changes mirage-qubes-ipv4
  Static_ipv4.Make now requires a Random device and a monotonic clock
  connect requires a Mclock.t
  Mirage_protocols_lwt.IPV4 does not define the type alias ethif (#83 @hannesm)
* build: various fixes (#71, #72 by @yomimono and @hannesm)

### v0.9 (2017-08-02)

* core: re-implement UDP checksum on input (#63 @haesbaert)
* client: implement renewal logic (breaking API change) (#60 @yomimono)
* client: split mirage sublibrary into lwt sublibrary (timing logic) and mirage sublibrary (shims for MirageOS APIs) (#60 @yomimono)
* numerous test and build bugfixes (#68 #64 #61 @samoht, #67 #66 #65 @djs55)

### v0.8 (2017-06-12)

* Port to Jbuilder (#57 @avsm).

### v0.7 (2017-14-04)

* Fixed a bug where only the first tuple from an option list would be parsed
* Fixed parsing of long option lists
* Fixed parsing for options 120 and 121
* Updated copyrights

### v0.6 (2017-04-01)

* `Dhcp_wire.buf_of_pkt` now correctly rejects empty options
* `Dhcp_wire.options_of_buf` now enforces minimun length on all cases
* Fixed option code for `Bcmcs_controller_ipv4_addr`
* **CRITICAL** Fixed a bug where `dhcp_flags` was read from the wrong offset
This bug was present in versions 0.4 and 0.5

### v0.5 (2017-03-14)

* Topkg support added
* Time type on input_pkt changed to int32
* Bump tcpip support to version 3.1.0

### v0.4 (2017-01-21)

* MirageOS3 compatibility
* Ocaml 4.02.3 deprecated
* Fixed lease database bug
* Converted to Result.t
* IP-address range on subnet made optional
* Added Lease.to_string
* Travis support
* Improved default lease time
* Fixed cases where pkt_of_buf could raise an exception

### v0.3 (2016-04-02)

* Fixed uninitialized data on packet parsing, normalized to zero
* Lease.database moved out of Config.t
* Leases are now purely functional
* Garbage collect function added
* Moved Lease into Dhcp_server.Lease
* Config.subnet merged into Config.t
* Convert to ppx
* Minor bug fixes

### v0.2 (2015-11-10)

* Custom exceptions removed, only Invalid_argument now
* Improved mli documentation
* Major rewrite
* Support ocaml 4.01

### v0.1 (2015-10-09)

* Initial release
