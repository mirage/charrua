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

(** {1 DHCP Server } *)

(** A DHCP server is composed of two sub-modules: {! Config} and {! Input}.  The
    former deals with building a suitable configuration for using with the
    later. *)

(** {2 DHCP Server Configuration } *)

module Config : sig

  type host = {
    hostname : string;
    options : Dhcp_wire.dhcp_option list;
    fixed_addr : Ipaddr.V4.t option;
    hw_addr : Macaddr.t option;
  }
  (** {! host} config section entry. *)

  val host_of_sexp : Sexplib.Sexp.t -> host
  val sexp_of_host : host -> Sexplib.Sexp.t

  type subnet = {
    ip_addr : Ipaddr.V4.t;
    mac_addr : Macaddr.t;
    network : Ipaddr.V4.Prefix.t;
    range : Ipaddr.V4.t * Ipaddr.V4.t;
    options : Dhcp_wire.dhcp_option list;
    hosts : host list;
    default_lease_time : int32 option;
    max_lease_time : int32 option;
  }
  (** {! subnet} config section entry *)

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
  (** Server configuration *)

  val t_of_sexp : Sexplib.Sexp.t -> t
  val sexp_of_t : t -> Sexplib.Sexp.t

  val parse : string -> (Ipaddr.V4.Prefix.addr * Macaddr.t) list -> t
  (** [parse cf l] Creates a server configuration by parsing [cf] as an ISC
      dhcpd.conf file, currently only the options at [sample/dhcpd.conf] are
      supported. [l] is a list of network addresses, each pair is the output
      address to be used for building replies and each must match a [network
      section] of [cf]. A normal usage would be a list of all interfaces
      configured in the system *)
end

(** {2 DHCP Leases (bindings) } *)

module Lease : sig
  type t

  val sexp_of_t : t -> Sexplib.Sexp.t
  val t_of_sexp : Sexplib.Sexp.t -> t

  val make_fixed : Macaddr.t -> Ipaddr.V4.t -> now:float -> t
  val timeleft : t -> now:float -> int32
  val timeleft_exn : t -> now:float -> int32
  val timeleft3 : t -> float -> float -> now:float -> int32 * int32 * int32
  val extend : t -> now:float -> t
  val expired : t -> now:float -> bool

  type database

  val make_db : unit -> database
  val garbage_collect : database -> now:float -> database
  val remove : t -> database -> database
  val replace : t -> database -> database
  val lease_of_client_id : Dhcp_wire.client_id -> database -> t option
  val lease_of_addr : Ipaddr.V4.t -> database -> t option
  val addr_allocated : Ipaddr.V4.t -> database -> bool
  val addr_available : Ipaddr.V4.t -> database -> now:float -> bool
  val get_usable_addr :
    Dhcp_wire.client_id ->
    database -> Ipaddr.V4.t * Ipaddr.V4.t -> now:float -> Ipaddr.V4.t option

end

(** {2 DHCP Input Packet Logic } *)

module Input : sig

  (** The logic for handling a DHCP input packet is pure, the module does not
      perform any IO, it only returns a possible reply packet or event to be
      logged.

      A typical server main loop would do its own IO for receiving a packet,
      then input with {! Input.input_pkt} and send out the resulting reply. *)

  type result =
    | Silence (** Input packet didn't belong to us, normal nop event.*)
    | Update of Lease.database (** Lease database update. *)
    | Reply of Dhcp_wire.pkt * Lease.database
    (** Reply packet to be sent on the same subnet and the corresponding lease
        database to be used in case the sent of the reply pkt is successfull *)
    | Warning of string (** An odd event, could be logged. *)
    | Error of string (** Input packet is invalid, or some other error ocurred. *)
    (** The result of [input_pkt]. *)

  val for_subnet : Dhcp_wire.pkt -> Config.subnet -> bool
  (** True if the packet is destined for this subnet. *)

  val input_pkt : Config.t -> Lease.database -> Config.subnet ->
    Dhcp_wire.pkt -> float -> result
  (** [input_pkt config lease_db subnet pkt time] Inputs packet [pkt], lease_db
      is the current lease database state, the resulting action should be
      performed by the caller, normally a [Reply] packet is returned and must be
      sent on the same subnet. [time] is a float representing time as in
      [Unix.time] or Mirage's [Clock.time]. *)
end
