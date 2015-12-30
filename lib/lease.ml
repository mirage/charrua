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

module Client_id = struct
  open Dhcp_wire

  type t = client_id

  let compare a b =
    match a, b with
    | Hwaddr maca,  Hwaddr macb -> Macaddr.compare maca macb
    | Id ida,  Id idb -> String.compare ida idb
    | Id _, Hwaddr _ -> -1
    | Hwaddr _, Id _ -> 1
end

module Addr_map = Map.Make(Ipaddr.V4)
module Id_map = Map.Make(Client_id)

(* Lease (dhcp bindings) operations *)
type t = {
  tm_start   : int32;
  tm_end     : int32;
  addr       : Ipaddr.V4.t;
  client_id  : Dhcp_wire.client_id;
} with sexp

(* Database, collection of leases *)
type database = {
  id_map : t Id_map.t;
  addr_map : t Addr_map.t;
} (* with sexp *)

let update_db id_map addr_map =
  { id_map; addr_map }

let make_db () = update_db Id_map.empty Addr_map.empty

let make client_id addr ~duration ~now =
  let tm_start = Int32.of_float now in
  let tm_end = Int32.add tm_start duration in
  { tm_start; tm_end; addr; client_id }

(* XXX defaults fixed leases to one hour, policy does not belong here. *)
let make_fixed mac addr ~now =
  make (Dhcp_wire.Hwaddr mac) addr ~duration:(Int32.of_int (60 * 60)) ~now

let remove lease db =
  update_db
    (Id_map.remove lease.client_id db.id_map)
    (Addr_map.remove lease.addr db.addr_map)

let replace lease db =
  (* First clear both maps *)
  let clr_map = remove lease db in
  update_db
    (Id_map.add lease.client_id lease clr_map.id_map)
    (Addr_map.add lease.addr lease clr_map.addr_map)

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

let garbage_collect db ~now =
  update_db
    (Id_map.filter (fun _ lease -> not (expired lease ~now)) db.id_map)
    (Addr_map.filter (fun _ lease -> not (expired lease ~now)) db.addr_map)

let lease_of_client_id client_id db = Util.find_some @@ fun () ->
  Id_map.find client_id db.id_map

let lease_of_addr addr db = Util.find_some @@ fun () ->
  Addr_map.find addr db.addr_map

let addr_allocated addr db =
  Util.true_if_some @@ lease_of_addr addr db

let addr_available addr db ~now =
  match lease_of_addr addr db with
  | None -> true
  | Some lease ->  not (expired lease ~now)

(*
 * We try to use the last 4 bytes of the mac address as a hint for the ip
 * address, if that fails, we try a linear search.
 *)
let get_usable_addr id db range ~now =
  let low_ip, high_ip = range in
  let low_32 = Ipaddr.V4.to_int32 low_ip in
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
  if not (addr_allocated hint_ip db) then
    Some hint_ip
  else match linear_loop Int32.zero (fun a -> not (addr_allocated a db)) with
    | Some ip -> Some ip
    | None -> linear_loop Int32.zero (fun a -> addr_available a db ~now)

