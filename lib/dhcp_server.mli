(*
 * Copyright (c) 2015 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

module Config : sig

  type host = {
    hostname : string;
    options : Dhcp_wire.dhcp_option list;
    fixed_addr : Ipaddr.V4.t option;
    hw_addr : Macaddr.t option;
  }
  val host_of_sexp : Sexplib.Sexp.t -> host
  val sexp_of_host : host -> Sexplib.Sexp.t

  type subnet = {
    ip_addr : Ipaddr.V4.t;
    mac_addr : Macaddr.t;
    network : Ipaddr.V4.Prefix.t;
    range : Ipaddr.V4.t * Ipaddr.V4.t;
    options : Dhcp_wire.dhcp_option list;
    lease_db : Lease.database;
    hosts : host list;
    default_lease_time : int32 option;
    max_lease_time : int32 option;
  }
  val subnet_of_sexp : Sexplib.Sexp.t -> subnet
  val sexp_of_subnet : subnet -> Sexplib.Sexp.t

  type t = {
    addresses : (Ipaddr.V4.t * Macaddr.t) list;
    subnets : subnet list;
    options : Dhcp_wire.dhcp_option list;
    hostname : string;
    default_lease_time : int32;
    max_lease_time : int32;
  }
  val t_of_sexp : Sexplib.Sexp.t -> t
  val sexp_of_t : t -> Sexplib.Sexp.t

  exception Error of string
  val parse : string -> (Ipaddr.V4.Prefix.addr * Macaddr.t) list -> t
end

module Input : sig

  type result =
    | Silence
    | Reply of Dhcp_wire.pkt
    | Warning of string
    | Error of string

  val for_subnet : Dhcp_wire.pkt -> Config.subnet -> bool
  val input_pkt : Config.t -> Config.subnet -> Dhcp_wire.pkt -> float -> result
end
