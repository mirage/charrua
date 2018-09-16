### v0.10 2018-09-16

* charrua-unix: safe-string support (@haesbaert)
* Behave like a windows 10 (default requested options) (#76 @juga0)
* Document code using comments (#76 @juga0, #78 @yomimono)
* Support private_classless_static_route option (#76 @juga0)
* Adjust to tcpip 3.5.0 and mirage-protocols-lwt 1.4.0 changes mirage-qubes-ipv4
  Static_ipv4.Make now requires a Random device and a monotonic clock
  connect requires a Mclock.t
  Mirage_protocols_lwt.IPV4 does not define the type alias ethif (#83 @hannesm)

### v0.9 2017-08-02

* core: re-implement UDP checksum on input (#63 @haesbaert)
* client: implement renewal logic (breaking API change) (#60 @yomimono)
* client: split mirage sublibrary into lwt sublibrary (timing logic) and mirage sublibrary (shims for MirageOS APIs) (#60 @yomimono)
* numerous test and build bugfixes (#68 #64 #61 @samoht, #67 #66 #65 @djs55)

### v0.8 2017-06-12

* Port to Jbuilder (#57 @avsm).

### v0.7 2017-14-04

* Fixed a bug where only the first tuple from an option list would be parsed
* Fixed parsing of long option lists
* Fixed parsing for options 120 and 121
* Updated copyrights

### v0.6 2017-04-01

* `Dhcp_wire.buf_of_pkt` now correctly rejects empty options
* `Dhcp_wire.options_of_buf` now enforces minimun length on all cases
* Fixed option code for `Bcmcs_controller_ipv4_addr`
* **CRITICAL** Fixed a bug where `dhcp_flags` was read from the wrong offset
This bug was present in versions 0.4 and 0.5

### v0.5 2017-03-14

* Topkg support added
* Time type on input_pkt changed to int32
* Bump tcpip support to version 3.1.0

### v0.4 2017-01-21

* MirageOS3 compatibility
* Ocaml 4.02.3 deprecated
* Fixed lease database bug
* Converted to Result.t
* IP-address range on subnet made optional
* Added Lease.to_string
* Travis support
* Improved default lease time
* Fixed cases where pkt_of_buf could raise an exception

### v0.3 2016-04-02

* Fixed uninitialized data on packet parsing, normalized to zero
* Lease.database moved out of Config.t
* Leases are now purely functional
* Garbage collect function added
* Moved Lease into Dhcp_server.Lease
* Config.subnet merged into Config.t
* Convert to ppx
* Minor bug fixes

### v0.2 2015-11-10

* Custom exceptions removed, only Invalid_argument now
* Improved mli documentation
* Major rewrite
* Support ocaml 4.01

### v0.1 2015-10-09

* Initial release
