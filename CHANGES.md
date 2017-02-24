## 0.5 (??)

* Topkg support added
* Time type on input_pkt changed to int32

## 0.4 (2017-01-21)

* MirageOS3 compatibility
* Ocaml 4.02.3 deprecated
* Fixed lease database bug
* Converted to Result.t
* IP-address range on subnet made optional
* Added Lease.to_string
* Travis support
* Improved default lease time
* Fixed cases where pkt_of_buf could raise an exception

## 0.3 (2016-04-02)

* Fixed uninitialized data on packet parsing, normalized to zero
* Lease.database moved out of Config.t
* Leases are now purely functional
* Garbage collect function added
* Moved Lease into Dhcp_server.Lease
* Config.subnet merged into Config.t
* Convert to ppx
* Minor bug fixes

## 0.2 (2015-11-10)

* Custom exceptions removed, only Invalid_argument now
* Improved mli documentation.
* Major rewrite
* Support ocaml 4.01.

## 0.1 (2015-10-09)

* initial release
