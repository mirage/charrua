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

type level =
  | Notice
  | Info
  | Debug

let current_level = ref Notice

let str_of_level = function
  | Notice -> "notice"
  | Info -> "info"
  | Debug -> "debug"

let level_of_str l = match (String.lowercase l) with
  | "notice" -> Notice
  | "info" -> Info
  | "debug" -> Debug
  | _ -> invalid_arg ("Invalid level: " ^ l)

let klog k ?pre level fmt =
  let p = match pre with
    | None -> ""
    | Some pre -> pre ^ ": "
  in
  if !current_level >= level then
    Printf.kfprintf k stderr ("%s" ^^ fmt ^^ "\n%!") p
  else
    Printf.ikfprintf k stderr fmt

let log ?pre level fmt = klog (fun _ -> ()) ?pre level fmt
let log_lwt ?pre level fmt = klog (fun _ -> Lwt.return_unit) ?pre level fmt

let notice fmt = log Notice fmt
let warn fmt = log ~pre:"warn" Notice fmt
let info fmt = log ~pre:"info" Info fmt
let debug fmt = log ~pre:"debug" Debug fmt

let notice_lwt fmt = log_lwt Notice fmt
let warn_lwt fmt = log_lwt ~pre:"warn" Notice fmt
let info_lwt fmt = log_lwt ~pre:"info" Info fmt
let debug_lwt fmt = log_lwt ~pre:"debug" Debug fmt
