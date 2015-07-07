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

open Sexplib.Conv

exception Error of string

type host = {
  hostname : string;
  options : Dhcp.dhcp_option list;
  fixed_addr : Ipaddr.V4.t option;
  hw_addr : Macaddr.t option;
} with sexp

type interface = {
  name : string;
  id : int;
  addr : Ipaddr.V4.t;
} with sexp

type subnet = {
  interface : interface;
  network : Ipaddr.V4.Prefix.t;
  range : Ipaddr.V4.t * Ipaddr.V4.t;
  options : Dhcp.dhcp_option list;
  hosts : host list;
  default_lease_time : int32 option;
  max_lease_time : int32 option;
} with sexp

type t = {
  interfaces : interface list;
  subnets : subnet list;
  options : Dhcp.dhcp_option list;
  hostname : string;
  default_lease_time : int32;
  max_lease_time : int32;
} with sexp

(* The structures returned when parsing the config file *)
type subnet_ast = {
  network : Ipaddr.V4.Prefix.t;
  range : Ipaddr.V4.t * Ipaddr.V4.t;
  options : Dhcp.dhcp_option list;
  hosts : host list;
  default_lease_time : int32 option;
  max_lease_time : int32 option;
} with sexp

type ast = {
  subnets : subnet_ast list;
  options : Dhcp.dhcp_option list;
  default_lease_time : int32;
  max_lease_time : int32;
} with sexp

let get_interfaces () =
  List.map (function
      | name, (addr, _) ->
        let id = Util.if_nametoindex name in
        Log.debug "Got interface name:%s id:%d addr:%s"
          name id (Ipaddr.V4.to_string addr);
        { name; id; addr})
    (Tuntap.getifaddrs_v4 ())

let config_of_ast ast =
  let interfaces = get_interfaces () in
  let subnets = List.map (fun subnet ->
      let interface = try List.find (function ifnet ->
          Ipaddr.V4.Prefix.mem ifnet.addr subnet.network) interfaces
        with Not_found ->
          raise (Error ("No interface address for network " ^
                        (Ipaddr.V4.Prefix.to_string subnet.network)))
      in
      let () = List.iter (fun host ->
          match host.fixed_addr with
          | None -> ()
          | Some addr -> if not (Ipaddr.V4.Prefix.mem addr subnet.network) then
              raise (Error ("Fixed address " ^ (Ipaddr.V4.to_string addr) ^
                            " does not belong to subnet " ^
                            (Ipaddr.V4.Prefix.to_string subnet.network))))
          subnet.hosts
      in
      { interface = interface;
        network = subnet.network;
        range = subnet.range;
        options = subnet.options;
        hosts = subnet.hosts;
        default_lease_time = subnet.default_lease_time;
        max_lease_time = subnet.max_lease_time })
      ast.subnets
  in
  { interfaces; subnets;
    options = ast.options;
    hostname = Unix.gethostname ();
    default_lease_time = ast.default_lease_time;
    max_lease_time = ast.max_lease_time }

let subnet_of_ifid (config : t) ifid = try
    Some (List.find (fun subnet -> subnet.interface.id = ifid) config.subnets)
  with Not_found -> None

let default_lease_time (config : t) (subnet : subnet) =
  match subnet.default_lease_time with
  | Some time -> time
  | None -> config.default_lease_time

let lease_time_good (config : t) (subnet : subnet) time =
  let max_lease_time = match subnet.max_lease_time with
    | Some time -> time
    | None -> config.max_lease_time
  in
  time <= max_lease_time
