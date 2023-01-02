(*
 * Copyright (c) 2022 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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

let () = Printexc.record_backtrace true

let filter_map f l = List.rev @@
  List.fold_left (fun a v -> match f v with Some v' -> v'::a | None -> a) [] l

(* Drop privileges and chroot to _charruad home *)
let go_safe user group =
  let (pw, _gr) = try
      (Unix.getpwnam user, Unix.getgrnam group)
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
      Unix.setgid oegid;
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
  Bytes.to_string buf

let go_daemon () =
  ignore @@ Unix.umask 0o022;   (* good practice *)
  if Unix.fork () > 0 then
    exit 0;
  ignore @@ Unix.setsid ();
  Unix.chdir "/";               (* good practice, we do it again *)
  let null = Unix.openfile "/dev/null" [ Unix.O_RDWR ] 0o666 in
  Unix.dup2 null Unix.stdin;
  Unix.dup2 null Unix.stdout;
  Unix.dup2 null Unix.stderr;
  Unix.close null

let init_log level daemon =
  Logs.set_reporter @@
  if daemon then
    Logs_syslog_unix.unix_reporter () |> Result.get_ok
  else
    Logs.format_reporter ();
  Logs.Src.set_level Logs.default @@
  Result.get_ok @@ Logs.level_of_string level

let uptime_in_sec () =
  Int64.div (Mtime_clock.elapsed_ns ()) (Int64.of_int 1_000_000_000) |> Int64.to_int

let maybe_gc db now gbcol =
  if (now - gbcol) >= 60 then
    let () = Logs.debug (fun m -> m  "Garbage collecting...") in
    Dhcp_server.Lease.garbage_collect db ~now:(Int32.of_int now), now + 60
  else
    (db, gbcol)

let rec input config db link gbcol =
  let open Dhcp_server.Input in

  let buf = Eio_rawlink.read_packet link in
  let now = uptime_in_sec () in
  let db, gbcol = maybe_gc db now gbcol in
  let db = match Dhcp_wire.pkt_of_buf buf (Cstruct.length buf) with
    | Error e -> Logs.err (fun m -> m "%s" e); db
    | Ok pkt ->
      Logs.debug (fun m -> m "Received packet: %s" (Dhcp_wire.pkt_to_string pkt));
      match (input_pkt config db pkt (Int32.of_int now)) with
      | Silence -> db
      | Update db -> db
      | Reply (reply, db) ->
        Eio_rawlink.send_packet link (Dhcp_wire.buf_of_pkt reply);
        Logs.debug (fun m -> m "Sent reply packet: %s" (Dhcp_wire.pkt_to_string reply));
        db
      | Warning w -> Logs.warn (fun m -> m "%s" w); db
      | Error e -> Logs.err (fun m -> m "%s" e); db
  in
  input config db link gbcol

let ifname_of_address ip_addr interfaces =
  let ifnet =
    List.find
      (function _name, cidr ->
         Ipaddr.V4.compare ip_addr (Ipaddr.V4.Prefix.address cidr) = 0)
      interfaces
  in
  match ifnet with name, _ -> name

let charruad configfile group pidfile user verbosity daemonize =
  let open Dhcp_server.Config in
  let open Dhcp_server.Lease in

  init_log verbosity daemonize;
  let interfaces = Tuntap.getifaddrs_v4 () in
  let addresses = List.map
      (function name, cidr -> (Ipaddr.V4.Prefix.address cidr, Tuntap.get_macaddr name))
      interfaces
  in
  let configtxt = read_file configfile in
  let db = make_db () in
  if daemonize then
    go_daemon ();
  Logs.info (fun m -> m "Charrua DHCPD starting");
  (* Open pidfile before dropping priviledges *)
  let pidc = open_out pidfile in
  Printf.fprintf pidc "%d" (Unix.getpid ());
  close_out pidc;

  Eio_main.run @@ fun _env ->
  Eio.Switch.run @@ fun sw ->
  (* Filter out the addresses which have networks assigned *)
  let threads = filter_map
      (fun addr_tuple ->
         let addr = fst addr_tuple in
         let s = Ipaddr.V4.to_string addr in
         let config = try Some (parse configtxt addr_tuple) with Not_found -> None in
         match config with
         | Some config ->
           Logs.info (fun m -> m "Found network for %s" s);
           (* Get a rawlink on the interface *)
           let ifname = ifname_of_address addr interfaces in
           let link = Eio_rawlink.(open_link ~sw ~filter:(dhcp_server_filter ()) ifname) in
           Some (fun () -> input config db link (uptime_in_sec ()))
         | None -> Logs.debug (fun m -> m "No network found for %s" s); None)
      addresses
  in
  if List.length threads = 0 then
    failwith "Could not match any interface address with any network section.";

  (* Links have been opened, files have been written, we can drop priviledges *)
  go_safe user group;

  let () = Eio.Fiber.any threads in
  Logs.info (fun m -> m "Charrua DHCPD exiting");

(* Parse command line and start the ball *)
open Cmdliner
let cmd =
  let configfile = Arg.(value & opt string "/etc/charruad.conf" & info ["c" ; "config"]
                          ~doc:"Configuration file path.") in
  let group = Arg.(value & opt string "_charruad" & info ["g" ; "group"]
                         ~doc:"Group to run as.") in
  let pidfile = Arg.(value & opt string "/run/charruad.pid" & info ["p" ; "pidfile"]
                          ~doc:"Pid file path.") in
  let user = Arg.(value & opt string "_charruad" & info ["u" ; "user"]
                         ~doc:"User to run as.") in
  let verbosity = Arg.(value & opt string "info" & info ["v" ; "verbosity"]
                         ~doc:"Log verbosity, warning|info|debug") in
  let daemonize = Arg.(value & flag & info ["D" ; "daemon"]
                         ~doc:"Daemonize.") in
  Cmd.v
    (Cmd.info "charruad" ~version:"%%VERSION%%" ~doc:"Charrua DHCPD")
    Term.(const charruad $ configfile $ group $ pidfile $ user $ verbosity $ daemonize)

let () = exit (Cmd.eval cmd)
