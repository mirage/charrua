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

let find_map f t =
  let rec loop = function
    | [] -> None
    | x :: l ->
      match f x with
      | None -> loop l
      | Some _ as r -> r
  in
  loop t

let filter_map f l = List.rev @@
  List.fold_left (fun a v -> match f v with Some v' -> v'::a | None -> a) [] l

let finalize f g =
  try
    let x = f () in
    g ();
    x
  with exn ->
    g ();
    raise exn

let bytes_extend_if_le s m =
  let n = Bytes.length s in
  if n > m then
    invalid_arg ("string is too damn big: " ^ (string_of_int n));
  let e = Bytes.extend s 0 (m - n) in
  Bytes.fill e n (m - n) (Char.chr 0);
  e

let bytes_nul b =
  let len = Bytes.length b in
  let rec loop i =
    if i = len then
      true
    else if (Bytes.get b i) <> (Char.chr 0) then
      false
    else
      loop (succ i)
  in
  loop 0

let cstruct_copy_normalized f buf =
  let b = f buf in
  if bytes_nul b then "" else b

let some_or_default x d = match x with Some x -> x | None -> d
let some_or_f x f = match x with Some x -> x | None -> f ()
let some_or_invalid x s = some_or_f x (fun () -> invalid_arg s)
let some_or_fail x s = some_or_f x (fun () -> failwith s)
let find_some f = try Some (f ()) with Not_found -> None
let true_if_some x = match x with Some _ -> true | None -> false

let cons v tl = v :: tl
let cons_if p v tl = if p then v :: tl else tl
let cons_if_some v tl = match v with Some v -> v :: tl | None -> tl
let cons_if_some_f v fnr tl = match v with Some x -> fnr x :: tl | None -> tl

let addr_in_range addr range =
  let (low_ip, high_ip) = range in
  let low_32 = (Ipaddr.V4.to_int32 low_ip) in
  let high_32 = Ipaddr.V4.to_int32 high_ip in
  let addr_32 = Ipaddr.V4.to_int32 addr in
  addr_32 >= low_32 && addr_32 <= high_32
