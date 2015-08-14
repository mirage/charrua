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

let filter_map f l =
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
  Bytes.extend s 0 (m - n)

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

let cons v tl = v :: tl
let cons_if p v tl = if p then v :: tl else tl
let cons_if_some v tl = match v with Some v -> v :: tl | None -> tl
let cons_if_some_f v fnr tl = match v with Some x -> fnr x :: tl | None -> tl

(* C stubs from stubs.c *)
(* XXX Move all to ctypes some day *)
external if_indextoname: int -> string = "caml_if_indextoname"
external if_nametoindex: string -> int = "caml_if_nametoindex"
external reqif: Unix.file_descr -> unit = "caml_reqif"
external recvif: Unix.file_descr -> Lwt_bytes.t -> int -> int -> (int * int) =
  "caml_recvif"
external ones_complement: Cstruct.t -> int = "caml_tcpip_ones_complement_checksum"

let lwt_recvif fd buf pos len =
  let open Lwt.Infix in
  let open Lwt_unix in
  let open Lwt_bytes in
  if pos < 0 || len < 0 || pos > length buf - len then
    invalid_arg "bad pos/len"
  else
    blocking fd >>= function
    | true -> failwith "socket must be nonblocking"
    | false ->
      wrap_syscall Read fd (fun () -> recvif (unix_file_descr fd) buf pos len)

let lwt_cstruct_recvif fd t =
  lwt_recvif fd t.Cstruct.buffer t.Cstruct.off t.Cstruct.len
