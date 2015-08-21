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

open Lwt

let () = Printexc.record_backtrace true

let config_log verbosity =
  Log.current_level := Log.level_of_str verbosity

(* Drop privileges and chroot to _hdhcpd home *)
let go_safe () =
  let (pw, gr) = try
      (Unix.getpwnam "_hdhcpd", Unix.getgrnam "_hdhcpd")
    with _  ->
      failwith "No user and/or group _hdhcpd found, please create them."
  in
  Unix.chroot pw.Unix.pw_dir;
  Unix.chdir "/";
  (* Unix.setproctitle "hdhcpd"; XXX implement me *)
  Log.info "Chrooted to %s" pw.Unix.pw_dir;
  let ogid = Unix.getgid () in
  let oegid = Unix.getegid () in
  let ouid = Unix.getuid () in
  let oeuid = Unix.geteuid () in
  Unix.setgroups (Array.of_list [pw.Unix.pw_gid]);
  Unix.setgid pw.Unix.pw_gid;
  Unix.setuid pw.Unix.pw_uid;
  if ogid = pw.Unix.pw_gid ||
     oegid = pw.Unix.pw_gid ||
     ouid = pw.Unix.pw_uid ||
     oeuid = pw.Unix.pw_uid then
    failwith "Unexpected uid or gid after dropping privileges";
  (* Make sure we cant restore the old gid and uid *)
  let canrestore = try
      Unix.setuid ouid;
      Unix.setuid oeuid;
      Unix.setgid ogid;
      Unix.setuid oegid;
      true
    with _ -> false in
  if canrestore then
    failwith "Was able to restore UID, setuid is broken"

let hdhcpd configfile verbosity =
  let open Config in
  Printf.printf "Using configuration file: %s\n%!" configfile;
  Printf.printf "Haesbaert DHCPD started\n%!";
  let config = Config_parser.parse ~path:configfile () in
  let () = go_safe () in
  Lwt_main.run
    (Dhcp_server.start config verbosity >>=
     (fun _ -> return (Printf.printf "Haesbaert DHCPD finished\n%!")))

(* Parse command line and start the ball *)
open Cmdliner
let cmd =
  let verbosity = Arg.(value & opt string "notice" & info ["v" ; "verbosity"]
                         ~doc:"Log verbosity, debug|info|notice") in
  let configfile = Arg.(value & opt string "/etc/dhcpd.conf" & info ["c" ; "config"]
                          ~doc:"Configuration file path") in
  Term.(pure hdhcpd $ configfile $ verbosity),
  Term.info "hdhcpd" ~version:"0.1" ~doc:"Haesbaert DHCP"
let () = match Term.eval cmd with `Error _ -> exit 1 | _ -> exit 0
