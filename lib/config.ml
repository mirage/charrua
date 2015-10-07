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
open Sexplib.Std

exception Ast_error of string

type host = {
    hostname : string;
    options : Dhcp_wire.dhcp_option list;
    fixed_addr : Ipaddr.V4.t option;
    hw_addr : Macaddr.t option;
} with sexp

type subnet_ast = {
  network : Ipaddr.V4.Prefix.t;
  range : Ipaddr.V4.t * Ipaddr.V4.t;
  options : Dhcp_wire.dhcp_option list;
  hosts : host list;
  default_lease_time : int32 option;
  max_lease_time : int32 option;
} with sexp

type ast = {
  subnets : subnet_ast list;
  options : Dhcp_wire.dhcp_option list;
  default_lease_time : int32;
  max_lease_time : int32;
} with sexp

module Make (I : Dhcp_S.INTERFACE) = struct
  open Sexplib.Conv

  exception Error of string

  type interface = I.t sexp_opaque with sexp

  type subnet = {
    interface : interface;
    network : Ipaddr.V4.Prefix.t;
    range : Ipaddr.V4.t * Ipaddr.V4.t;
    options : Dhcp_wire.dhcp_option list;
    lease_db : Lease.database;
    hosts : host list;
    default_lease_time : int32 option;
    max_lease_time : int32 option;
  } with sexp

  type t = {
    interfaces : interface list;
    subnets : subnet list;
    options : Dhcp_wire.dhcp_option list;
    hostname : string;
    default_lease_time : int32;
    max_lease_time : int32;
  } with sexp

  (* The structures returned when parsing the config file *)
  let config_of_ast (ast : ast) interfaces =
    let subnet_of_subnet_ast (s : subnet_ast) =
        let interface = try List.find (function ifnet ->
            Ipaddr.V4.Prefix.mem (I.addr ifnet) s.network) interfaces
          with Not_found ->
            raise (Error ("No interface address for network " ^
                          (Ipaddr.V4.Prefix.to_string s.network)))
        in
        let () = List.iter (fun host ->
            match host.fixed_addr with
            | None -> ()
            | Some addr ->
              if not (Ipaddr.V4.Prefix.mem addr s.network) then
                raise (Error (Printf.sprintf "Fixed address %s does not \
                                              belong to subnet %s"
                                (Ipaddr.V4.to_string addr)
                                (Ipaddr.V4.Prefix.to_string s.network)))
              else if Util.addr_in_range addr s.range then
                match s.range with
                | low, high ->
                  raise (Error (Printf.sprintf "Fixed address %s must be \
                                                outside of range %s:%s"
                                  (Ipaddr.V4.to_string addr)
                                  (Ipaddr.V4.to_string low)
                                  (Ipaddr.V4.to_string high))))
            s.hosts
        in
        let fixed_addrs = List.fold_left
            (fun alist host -> match (host.fixed_addr, host.hw_addr) with
               | Some fixed_addr, Some hw_addr -> (hw_addr, fixed_addr) :: alist
               | _ -> alist)
            [] s.hosts
        in
        let db_name = (I.name interface) ^ ":" ^
                      (Ipaddr.V4.Prefix.to_string s.network)
        in
        { interface = interface;
          network = s.network;
          range = s.range;
          options = s.options;
          lease_db = Lease.make_db db_name s.network s.range fixed_addrs;
          hosts = s.hosts;
          default_lease_time = s.default_lease_time;
          max_lease_time = s.max_lease_time }
    in
    let subnets = List.map subnet_of_subnet_ast ast.subnets in
    { interfaces; subnets;
      options = ast.options;
      hostname = "Charrua DHCP Server"; (* XXX Implement server-name option. *)
      default_lease_time = ast.default_lease_time;
      max_lease_time = ast.max_lease_time }

  let t1_time_ratio = 0.5
  let t2_time_ratio = 0.8

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
end
