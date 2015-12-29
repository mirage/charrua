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

(* Lease (dhcp bindings) operations *)
type t = {
  tm_start   : int32;
  tm_end     : int32;
  addr       : Ipaddr.V4.t;
  client_id  : Dhcp_wire.client_id;
} with sexp

(* Database, collection of leases *)
type database = {
  range : Ipaddr.V4.t * Ipaddr.V4.t;
  table : (Dhcp_wire.client_id, t) Hashtbl.t;
  fixed_table : (Macaddr.t, Ipaddr.V4.t) Hashtbl.t;
} with sexp

let make_db range fixed_addrs =
  let fixed_table = Hashtbl.create 10 in
  List.iter (function (mac, addr) -> Hashtbl.add fixed_table mac addr) fixed_addrs;
  { range; table = Hashtbl.create 10; fixed_table }

let make client_id addr ~duration ~now =
  let tm_start = Int32.of_float now in
  let tm_end = Int32.add tm_start duration in
  { tm_start; tm_end; addr; client_id }

(* XXX defaults fixed leases to one hour, policy does not belong here. *)
let make_fixed mac addr ~now =
  make (Dhcp_wire.Hwaddr mac) addr ~duration:(Int32.of_int (60 * 60)) ~now

let lookup client_id mac lease_db ~now =
  match (Util.find_some (fun () -> Hashtbl.find lease_db.fixed_table mac)) with
  | Some addr -> Some (make_fixed mac addr ~now)
  | None -> Util.find_some (fun () -> Hashtbl.find lease_db.table client_id)

let replace client_id mac lease lease_db =
  match (Util.find_some (fun () -> Hashtbl.find lease_db.fixed_table mac)) with
  | Some addr -> ()
  | None -> Hashtbl.replace lease_db.table client_id lease

let remove client_id mac lease_db =
  match (Util.find_some (fun () -> Hashtbl.find lease_db.fixed_table mac)) with
  | Some addr -> ()
  | None -> Hashtbl.remove lease_db.table client_id

let timeleft lease ~now =
  let left = (Int32.to_float lease.tm_end) -. now in
  if left < 0. then Int32.zero else (Int32.of_float left)

let timeleft_exn lease ~now =
  let left = timeleft lease ~now in
  if left = Int32.zero then invalid_arg "No time left for lease" else left

let timeleft3 lease t1_ratio t2_ratio ~now =
  let left = Int32.to_float (timeleft lease ~now) in
  (Int32.of_float left,
   Int32.of_float (left *. t1_ratio),
   Int32.of_float (left *. t2_ratio))

let extend lease ~now =
  let original = Int32.sub lease.tm_end lease.tm_start in
  make lease.client_id lease.addr ~duration:original ~now

let expired lease ~now = timeleft lease ~now = Int32.zero

let to_list lease_db = Hashtbl.fold (fun _ v acc -> v :: acc ) lease_db.table []
let to_string x = Sexplib.Sexp.to_string_hum (sexp_of_t x)

let addr_in_range mac addr lease_db =
  match (Util.find_some (fun () -> Hashtbl.find lease_db.fixed_table mac)) with
  (* If this is a fixed address, it's always good. *)
  | Some fixed_addr -> addr = fixed_addr
  | None ->
  (* When not, address should respect the range. *)
    let (low_ip, high_ip) = lease_db.range in
    let low_32 = (Ipaddr.V4.to_int32 low_ip) in
    let high_32 = Ipaddr.V4.to_int32 high_ip in
    let addr_32 = Ipaddr.V4.to_int32 addr in
    addr_32 >= low_32 && addr_32 <= high_32

let leases_of_addr addr lease_db =
  List.filter (fun l -> l.addr = addr) (to_list lease_db)

let addr_allocated addr lease_db =
  match (leases_of_addr addr lease_db) with
  | [] -> false
  | _ -> true

let addr_available addr lease_db ~now =
  match (leases_of_addr addr lease_db) with
  | [] -> true
  | leases -> not (List.exists (fun l -> not (expired l ~now)) leases)

(*
 * We try to use the last 4 bytes of the mac address as a hint for the ip
 * address, if that fails, we try a linear search.
 *)
let get_usable_addr id lease_db ~now =
  let (low_ip, high_ip) = lease_db.range in
  let low_32 = (Ipaddr.V4.to_int32 low_ip) in
  let high_32 = Ipaddr.V4.to_int32 high_ip in
  if (Int32.compare low_32 high_32) >= 0 then
    invalid_arg "invalid range, must be (low * high)";
  let hint_ip =
    let v = match id with
      | Dhcp_wire.Id s -> Int32.of_int 1805 (* XXX who cares *)
      | Dhcp_wire.Hwaddr hw ->
        let s = Bytes.sub (Macaddr.to_bytes hw) 2 4 in
        let b0 = Int32.shift_left (Char.code s.[3] |> Int32.of_int) 0 in
        let b1 = Int32.shift_left (Char.code s.[2] |> Int32.of_int) 8 in
        let b2 = Int32.shift_left (Char.code s.[1] |> Int32.of_int) 16 in
        let b3 = Int32.shift_left (Char.code s.[0] |> Int32.of_int) 24 in
        Int32.zero |> Int32.logor b0 |> Int32.logor b1 |>
        Int32.logor b2 |> Int32.logor b3
    in
    Int32.rem v (Int32.sub (Int32.succ high_32) low_32) |>
    Int32.abs |>
    Int32.add low_32 |>
    Ipaddr.V4.of_int32
  in
  let rec linear_loop off f =
    let ip = Ipaddr.V4.of_int32 (Int32.add low_32 off) in
    if f ip then
      Some ip
    else if off = high_32 then
      None
    else
      linear_loop (Int32.succ off) f
  in
  if not (addr_allocated hint_ip lease_db) then
    Some hint_ip
  else match linear_loop Int32.zero (fun a -> not (addr_allocated a lease_db)) with
    | Some ip -> Some ip
    | None -> linear_loop Int32.zero (fun a -> addr_available a lease_db ~now)

