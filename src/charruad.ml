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

(* Drop privileges and chroot to _charruad home *)
let go_safe () =
  let (pw, gr) = try
      (Unix.getpwnam "_charruad", Unix.getgrnam "_charruad")
    with _  ->
      failwith "No user and/or group _charruad found, please create them."
  in
  Unix.chroot pw.Unix.pw_dir;
  Unix.chdir "/";
  (* Unix.setproctitle "charruad"; XXX implement me *)
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

let read_file f =
  let ic = open_in f in
  let n = in_channel_length ic in
  let buf = Bytes.create n in
  really_input ic buf 0 n;
  close_in ic;
  buf

let filter_map f l =
  List.fold_left (fun a v -> match f v with Some v' -> v'::a | None -> a) [] l

module I = struct

  type t = {
    name : string;
    addr : Ipaddr.V4.t;
    mac  : Macaddr.t;
    link : Lwt_rawlink.t;
  }

  let name t = t.name
  let addr t = t.addr
  let send t buf = Lwt_rawlink.send_packet t.link buf
  let recv t = Lwt_rawlink.read_packet t.link
  let mac t = t.mac
  let interface_list networks =
    filter_map (function
      | name, (addr, _) ->
        let mac = Tuntap.get_macaddr name in
        try
          let _ = List.find
              (fun network -> Ipaddr.V4.Prefix.mem addr network) networks
          in
          Some { name; addr; mac;
                 link = Lwt_rawlink.(open_link ~filter:(dhcp_filter ()) name) }
        with Not_found -> None)
      (Tuntap.getifaddrs_v4 ())

end

module D = Dhcp_server.Make (I) (Unix)

let logger_std cur_level level s =
  if cur_level >= level then
    match level with
    | Dhcp_logger.Notice -> print_endline s
    | _ -> prerr_endline s

let logger_color cur_level level s =
  let green s  = Printf.sprintf "\027[32m%s\027[m" s in
  let yellow s = Printf.sprintf "\027[33m%s\027[m" s in
  let blue s   = Printf.sprintf "\027[36m%s\027[m" s in
  let open Dhcp_logger in
  if cur_level >= level then
    match level with
    | Notice -> print_endline (green s)
    | Warn ->   prerr_endline (yellow s)
    | Debug ->  prerr_endline (blue s)

let go_daemon () =
  let syslogger = Lwt_log.syslog
      ~facility:`Daemon
      ~paths:["/dev/log"; "/var/run/log"; "/var/run/syslog"]
      ~template:"$(date) $(name)[$(pid)]: $(message)"
      ()
  in
  Lwt_log.default := syslogger;
  (* XXX Magic, don't remove this print...
     This print does the openlog in syslog, it has to be done now, before we
     drop priviledges, sadly Lwt doesn't provide a better way to do this.  *)
  Lwt_log.ign_warning "Garra Charrua !";
  Lwt_daemon.daemonize ~syslog:false ()

let charruad configfile verbosity daemonize color =
  let level = Dhcp_logger.level_of_str verbosity in
  let logger =
    if daemonize then
      logger_std level
    else
      match color with
      | `Auto | `Always -> logger_color level
      | `Never -> logger_std level
  in
  Dhcp_logger.init logger;
  let conf = read_file configfile in
  let networks = D.parse_networks conf in
  let interfaces = I.interface_list networks in
  let server = D.create conf interfaces in
  if daemonize then
    go_daemon ();
  go_safe ();
  logger Dhcp_logger.Notice "Charrua DHCPD started";
  Lwt_main.run (server >>= fun _ ->
                return (logger Dhcp_logger.Notice "Charrua DHCPD finished"))

(* Parse command line and start the ball *)
open Cmdliner
let cmd =
  let configfile = Arg.(value & opt string "/etc/dhcpd.conf" & info ["c" ; "config"]
                          ~doc:"Configuration file path") in
  let verbosity = Arg.(value & opt string "notice" & info ["v" ; "verbosity"]
                         ~doc:"Log verbosity, warn|notice|debug") in
  let daemonize = Arg.(value & flag & info ["D" ; "daemon"]
                         ~doc:"Daemonize") in
  let color =
    let when_enum = [ "always", `Always; "never", `Never; "auto", `Auto ] in
    let doc = Arg.info ~docv:"WHEN"
        ~doc:(Printf.sprintf "Colorize the output. $(docv) must be %s."
                (Arg.doc_alts_enum when_enum)) ["color"] in
    Arg.(value & opt (enum when_enum) `Auto & doc) in
  Term.(pure charruad $ configfile $ verbosity $ daemonize $ color),
  Term.info "charruad" ~version:"0.1" ~doc:"Charrua DHCPD"
let () = match Term.eval cmd with `Error _ -> exit 1 | _ -> exit 0
