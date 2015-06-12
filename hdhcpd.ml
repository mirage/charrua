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

let open_dhcp_sock () =
  let open Lwt_unix in
  let sock = socket PF_INET SOCK_DGRAM 0 in
  let () = setsockopt sock SO_REUSEADDR true in
  let () = setsockopt sock SO_BROADCAST true in
  let () = Util.reqif (unix_file_descr sock) in
  let () = bind sock (ADDR_INET (Unix.inet_addr_any, 67)) in
  sock

let input_discover config (subnet:Config.subnet) pkt leases =
  let open Dhcp in
  Log.debug "DISCOVER packet received %s" (Dhcp.str_of_pkt pkt);
  let lease = lease_of_pkt subnet.Config.range pkt leases in
  Log.debug "Got lease: %s" (str_of_lease lease);
  replace_lease (client_id_of_pkt pkt) lease leases

let valid_pkt pkt =
  let open Dhcp in
  if pkt.op <> Bootrequest then
    false
  else if pkt.htype <> Ethernet_10mb then
    false
  else if pkt.hlen <> 6 then
    false
  else if pkt.hops <> 0 then
    false
  else
    true

let input_pkt config ifid pkt leases =
  let open Dhcp in
  if valid_pkt pkt then
    (* Check if we have a subnet configured on the receiving interface *)
    match Config.subnet_of_ifid config ifid with
    | None -> Log.warn "No subnet for interface %s" (Util.if_indextoname ifid)
    | Some subnet ->
      match msgtype_of_options pkt.options with
      | Some DHCPDISCOVER -> input_discover config subnet pkt leases
      | None -> Log.warn "Got malformed packet: no dhcp msgtype"
      | Some m -> Log.debug "Unhandled msgtype %s" (str_of_msgtype m)
  else
    Log.warn "Invalid packet %s" (str_of_pkt pkt)

let rec dhcp_recv config sock leases =
  let buffer = Dhcp.make_buf () in
  lwt (n, ifid) = Util.lwt_cstruct_recvif sock buffer in
  Log.debug "dhcp sock read %d bytes on interface %s" n (Util.if_indextoname ifid);
  if n = 0 then
    failwith "Unexpected EOF in DHCPD socket";
  (* Input the packet *)
  let () = match (Dhcp.pkt_of_buf buffer n) with
    | exception Invalid_argument e ->
      Log.warn "Dropped packet: %s" e
    | pkt ->
      Log.debug "valid packet from %d bytes" n;
      try input_pkt config ifid pkt leases
      with Invalid_argument e -> Log.warn "Input pkt %s" e
  in
  dhcp_recv config sock leases

let hdhcpd configfile verbosity =
  let () = config_log verbosity in
  let () = Log.debug "Using configuration file: %s" configfile in
  let () = Log.notice "Haesbaert DHCPD started" in
  let config = Config_parser.parse ~path:configfile () in
  let sock = open_dhcp_sock () in
  let () = go_safe () in
  let recv_thread = dhcp_recv config sock (Dhcp.create_leases ()) in
  Lwt_main.run (recv_thread >>= fun () ->
    Log.notice_lwt "Haesbaert DHCPD finished")

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
