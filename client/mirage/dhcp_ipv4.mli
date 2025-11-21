(*
 * Copyright (c) 2010 Anil Madhavapeddy <anil@recoil.org>
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
module type S = sig
  module Net : Mirage_net.S
  module Ethernet : Ethernet.S
  module Arp : Arp.S
  module Ipv4 : Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t and type prefix = Ipaddr.V4.Prefix.t

  type t

  val lease : t -> Dhcp_wire.dhcp_option list option Lwt.t
  val net : t -> Net.t
  val ethernet : t -> Ethernet.t
  val arp : t -> Arp.t
  val ipv4 : t -> Ipv4.t
end

module type With_lease = sig
  type t
  val lease : t -> Dhcp_wire.dhcp_option list option Lwt.t
end

module Make (Network : Mirage_net.S) : sig
  include S

  val connect : ?no_init:bool -> ?cidr:Ipaddr.V4.Prefix.t -> ?gateway:Ipaddr.V4.t ->
    ?options:Dhcp_wire.dhcp_option list -> ?requests:Dhcp_wire.option_code list ->
    Network.t -> t Lwt.t
  (** Connect to an ipv4 device using information from a DHCP lease.
      If [cidr] is provided, no DHCP requests will be done, but instead a static
      IPv4 (Tcpip.Ip.S) stack will be used. If [no_init] is provided and [true],
      nothing will be initialized (for dual IPv4 and IPv6 stack where only the
      IPv6 part should be used). *)
end

module Proj_net (T : S) : sig
  include Mirage_net.S
  val connect : T.t -> t Lwt.t
end

module Proj_ethernet (T : S) : sig
  include Ethernet.S
  val connect : T.t -> t Lwt.t
end

module Proj_arp (T : S) : sig
  include Arp.S
  val connect : T.t -> t Lwt.t
end

module Proj_ipv4 (T : S) : sig
  include Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t and type prefix = Ipaddr.V4.Prefix.t
  val connect : T.t -> t Lwt.t
end

module Proj_lease (T : With_lease) : sig
  type t = Dhcp_wire.dhcp_option list option
  val connect : T.t -> t Lwt.t
end
