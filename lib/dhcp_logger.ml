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
  | Warn
  | Notice
  | Debug

let str_of_level = function
  | Warn -> "warn"
  | Notice -> "notice"
  | Debug -> "debug"

let level_of_str l = match (String.lowercase l) with
  | "warn" -> Warn
  | "notice" -> Notice
  | "debug" -> Debug
  | _ -> invalid_arg ("Invalid level: " ^ l)

let default_logger level s =
  match level with
  | Notice -> print_endline s
  | _ -> prerr_endline s

let logger = ref default_logger

let log level fmt = Printf.ksprintf (fun s -> !logger level s) fmt
let log_lwt level fmt = Printf.ksprintf (fun s -> Lwt.return (!logger level s)) fmt

let warn fmt = log Warn fmt
let notice fmt = log Notice fmt
let debug fmt = log Debug fmt

let warn_lwt fmt = log_lwt Warn fmt
let notice_lwt fmt = log_lwt Notice fmt
let debug_lwt fmt = log_lwt Debug fmt

let init loggerf =
  logger := loggerf
