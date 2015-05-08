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

exception Error of string

type host = {
  hostname : string;
  options : Dhcp.dhcp_option list;
  fixed_addr : Ipaddr.V4.t option;
  hw_addr : Macaddr.t option;
}

type subnet = {
  ifaddr : string * Ipaddr.V4.t;
  network : Ipaddr.V4.Prefix.t;
  range : Ipaddr.V4.t * Ipaddr.V4.t;
  options : Dhcp.dhcp_option list;
  hosts : host list;
}

type t = {
  ifaddrs : (string * Ipaddr.V4.t) list;
  subnets : subnet list;
  options : Dhcp.dhcp_option list;
}

(* The structures returned when parsing the config file *)
type subnet_ast = {
  network : Ipaddr.V4.Prefix.t;
  range : Ipaddr.V4.t * Ipaddr.V4.t;
  options : Dhcp.dhcp_option list;
  hosts : host list;
}

type ast = {
  subnets : subnet_ast list;
  options : Dhcp.dhcp_option list;
}

let config = ref { ifaddrs = []; subnets = []; options = []}

let config_of_ast ast ifaddrs =
  let subnets = List.map (fun subnet ->
      let ifaddr = try List.find (function _, addr ->
          Ipaddr.V4.Prefix.mem addr subnet.network) ifaddrs
        with Not_found ->
          raise (Error ("No interface address for network " ^
                        (Ipaddr.V4.Prefix.to_string subnet.network)))
      in
      { ifaddr = ifaddr;
        network = subnet.network;
        range = subnet.range;
        options = subnet.options;
        hosts = subnet.hosts })
      ast.subnets
  in
  { ifaddrs; subnets; options = ast.options }
