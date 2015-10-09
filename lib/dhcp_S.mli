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

(** {1 DHCP server signatures} *)

(** {2 INTERFACE } *)

module type INTERFACE = sig
  type t
  val send : t -> Cstruct.t -> unit Lwt.t (** [send] a packet from a [Cstruct.t] *)
  val recv : t -> Cstruct.t Lwt.t         (** [recv] packet a packet in a [Cstruct.t] *)
  val name : t -> string                  (** interface name *)
  val addr : t -> Ipaddr.V4.t             (** interface IP address *)
  val mac  : t -> Macaddr.t               (** interface MAC address *)
end
(** INTERFACE abstracts the idea of IO in a network interface. *)

(** {2 SERVER} *)

module type SERVER = sig
  type interface
  val create : string -> interface list -> 'a Lwt.t
  val parse_networks : string -> Ipaddr.V4.Prefix.t list
  (** Parse all the configured networks (the subnet statement),
      useful to discover which interfaces will be used. *)
end
