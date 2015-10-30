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

exception Syntax_error of string

type host = {
  hostname : string;
  options : Dhcp_wire.dhcp_option list;
  fixed_addr : Ipaddr.V4.t option;
  hw_addr : Macaddr.t option;
}

type subnet = {
  network : Ipaddr.V4.Prefix.t;
  range : Ipaddr.V4.t * Ipaddr.V4.t;
  options : Dhcp_wire.dhcp_option list;
  hosts : host list;
  default_lease_time : int32 option;
  max_lease_time : int32 option;
}

type t = {
  subnets : subnet list;
  options : Dhcp_wire.dhcp_option list;
  default_lease_time : int32;
  max_lease_time : int32;
}
