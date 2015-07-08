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

let input_decline config (subnet:Config.subnet) pkt =
  Log.debug "DECLINE packet received %s" (Dhcp.string_of_pkt pkt)

let input_release config (subnet:Config.subnet) pkt =
  Log.debug "RELEASE packet received %s" (Dhcp.string_of_pkt pkt)

let input_inform config (subnet:Config.subnet) pkt =
  Log.debug "INFORM packet received %s" (Dhcp.string_of_pkt pkt)

let input_request config (subnet:Config.subnet) pkt =
  let open Dhcp in
  let open Config in
  Log.debug "REQUEST packet received %s" (Dhcp.string_of_pkt pkt);
  let drop () = () in
  let lease_db = subnet.lease_db in
  let client_id = client_id_of_pkt pkt in
  let lease = Lease.lookup client_id lease_db in
  let ourip = subnet.interface.addr in
  let reqip = request_ip_of_options pkt.options in
  let sidip = server_identifier_of_options pkt.options in
  let nak ?msg () =
    let open Util in
    let nakpkt = {
      op = Bootreply;
      htype = Ethernet_10mb;
      hlen = 6;
      hops = 0;
      xid = pkt.xid;
      secs = 0;
      flags = pkt.flags; (* XXX this is WRONG !!! *)
      ciaddr = Ipaddr.V4.unspecified;
      yiaddr = Ipaddr.V4.unspecified;
      siaddr = Ipaddr.V4.unspecified;
      giaddr = pkt.giaddr; (* XXX this is WRONG !!! *)
      chaddr = pkt.chaddr;
      sname = "";
      file = "";
      options =
        cons (Message_type DHCPNAK) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f msg (fun msg -> Message msg) @@
        cons_if_some_f (client_id_of_options pkt.options)
          (fun id -> Client_id id) @@
        cons_if_some_f (vendor_class_id_of_options pkt.options)
          (fun vid -> Vendor_class_id vid) []
    }
    in
    Log.debug "REQUEST->NAK reply:\n%s" (string_of_pkt nakpkt)
  in
  let ack lease =
    let open Util in
    let lease_time, t1, t2 =
      Lease.timeleft3 lease Config.t1_time_ratio Config.t1_time_ratio
    in
    let ackpkt = {
      op = Bootreply;
      htype = Ethernet_10mb;
      hlen = 6;
      hops = 0;
      xid = pkt.xid;
      secs = 0;
      flags = pkt.flags; (* XXX this is WRONG !!! *)
      ciaddr = pkt.ciaddr;
      yiaddr = lease.Lease.addr;
      siaddr = ourip;
      giaddr = pkt.giaddr; (* XXX this is WRONG !!! *)
      chaddr = pkt.chaddr;
      sname = "";
      file = "";
      options =
        cons (Message_type DHCPACK) @@
        cons (Subnet_mask (Ipaddr.V4.Prefix.netmask subnet.network)) @@
        cons (Ip_lease_time lease_time) @@
        cons (Renewal_t1 t1) @@
        cons (Rebinding_t2 t2) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (vendor_class_id_of_options pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (parameter_requests_of_options pkt.options) with
         | Some preqs -> options_from_parameter_requests preqs subnet.options
         | None -> []
    }
    in
    assert (lease.Lease.client_id = client_id);
    Lease.replace client_id lease lease_db;
    Log.debug "REQUEST->ACK reply:\n%s" (string_of_pkt ackpkt)
  in
  match sidip, reqip, lease with
  | Some sidip, Some reqip, _ -> (* DHCPREQUEST generated during SELECTING state *)
    if sidip <> ourip then (* is it for us ? *)
      drop ()
    else if pkt.ciaddr <> Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 *)
      let () = Log.warn "Bad DHCPREQUEST, ciaddr is not 0" in
      drop ()
    else if not (Lease.addr_in_range reqip subnet.range) then
        nak ~msg:"Requested address is not in subnet range" ()
    else if not (Lease.addr_available reqip lease_db) then
      nak ~msg:"Requested address is not available" ()
    else
      ack (Lease.make client_id reqip (Config.default_lease_time config subnet))
  | None, Some reqip, Some lease ->   (* DHCPREQUEST @ INIT-REBOOT state *)
    let expired = Lease.expired lease in
    if pkt.ciaddr <> Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 *)
      let () = Log.warn "Bad DHCPREQUEST, ciaddr is not 0" in
      drop ()
    else if expired then
      nak ~msg:"Lease has expired, try again son" ()
    (* TODO check if it's in the correct network when giaddr <> 0 *)
    else if pkt.giaddr = Ipaddr.V4.unspecified &&
            not (Lease.addr_in_range reqip subnet.range) then
      nak ~msg:"Requested address is not in subnet range" ()
    else if lease.Lease.addr <> reqip then
      nak ~msg:"Requested address is incorrect" ()
    else
      ack lease
  | None, None, Some lease -> (* DHCPREQUEST @ RENEWING/REBINDING state *)
    let expired = Lease.expired lease in
    if pkt.ciaddr = Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 renewal *)
      let () = Log.warn "Bad DHCPREQUEST, ciaddr is 0" in
      drop ()
    else if expired then
      nak ~msg:"Lease has expired, try again son" ()
    else if lease.Lease.addr <> pkt.ciaddr then
      nak ~msg:"Requested address is incorrect" ()
    else
      ack lease
  | _ -> drop ()

let input_discover config (subnet:Config.subnet) pkt =
  let open Dhcp in
  let open Config in
  Log.debug "DISCOVER packet received %s" (Dhcp.string_of_pkt pkt);
  (* RFC section 4.3.1 *)
  (* Figure out the ip address *)
  let lease_db = subnet.lease_db in
  let id = client_id_of_pkt pkt in
  let lease = Lease.lookup id lease_db in
  let ourip = subnet.interface.addr in
  let expired = match lease with
    | Some lease -> Lease.expired lease
    | None -> false
  in
  let addr = match lease with
    (* Handle the case where we have a lease *)
    | Some lease ->
      if not expired then
        Some lease.Lease.addr
      (* If the lease expired, the address might not be available *)
      else if (Lease.addr_available lease.Lease.addr lease_db) then
        Some lease.Lease.addr
      else
        Lease.get_usable_addr id subnet.range lease_db
    (* Handle the case where we have no lease *)
    | None -> match (request_ip_of_options pkt.options) with
      | Some req_addr ->
        if (Lease.addr_in_range req_addr subnet.range) &&
           (Lease.addr_available req_addr lease_db) then
          Some req_addr
        else
          Lease.get_usable_addr id subnet.range lease_db
      | None -> Lease.get_usable_addr id subnet.range lease_db
  in
  (* Figure out the lease lease_time *)
  let lease_time = match (ip_lease_time_of_options pkt.options) with
    | Some ip_lease_time ->
      if Config.lease_time_good config subnet ip_lease_time then
        ip_lease_time
      else
        Config.default_lease_time config subnet
    | None -> match lease with
      | None -> Config.default_lease_time config subnet
      | Some lease -> if expired then
          Config.default_lease_time config subnet
        else
          Lease.timeleft lease
  in
  match addr with
  | None -> Log.warn "No ips left to offer !"
  | Some addr ->
    let open Util in
    (* Make a DHCPOFFER *)
    let op = Bootreply in
    let htype = Ethernet_10mb in
    let hlen = 6 in
    let hops = 0 in
    let xid = pkt.xid in
    let secs = 0 in
    let flags = pkt.flags in
    let ciaddr = Ipaddr.V4.any in
    let yiaddr = addr in
    let siaddr = ourip in
    let giaddr = pkt.giaddr in
    let chaddr = pkt.chaddr in
    let sname = config.Config.hostname in
    let file = "" in
    (* Start building the options *)
    let t1 = Int32.of_float (Config.t1_time_ratio *. (Int32.to_float lease_time)) in
    let t2 = Int32.of_float (Config.t2_time_ratio *. (Int32.to_float lease_time)) in
    (* These are the options we always give, even if not asked. *)
    let options =
      cons (Message_type DHCPOFFER) @@
      cons (Subnet_mask (Ipaddr.V4.Prefix.netmask subnet.network)) @@
      cons (Ip_lease_time lease_time) @@
      cons (Renewal_t1 t1) @@
      cons (Rebinding_t2 t2) @@
      cons (Server_identifier ourip) @@
      cons_if_some_f (vendor_class_id_of_options pkt.options)
        (fun vid -> Vendor_class_id vid) @@
      match (parameter_requests_of_options pkt.options) with
      | Some preqs -> options_from_parameter_requests preqs subnet.options
      | None -> []
    in
    let pkt = { op; htype; hlen; hops; xid; secs; flags;
                ciaddr; yiaddr; siaddr; giaddr; chaddr; sname; file;
                options }
    in
    Log.debug "DISCOVER reply:\n%s" (string_of_pkt pkt)

let input_pkt config ifid pkt =
  let open Dhcp in
  if valid_pkt pkt then
    (* Check if we have a subnet configured on the receiving interface *)
    match Config.subnet_of_ifid config ifid with
    | None -> Log.warn "No subnet for interface %s" (Util.if_indextoname ifid)
    | Some subnet ->
      match msgtype_of_options pkt.options with
      | Some DHCPDISCOVER -> input_discover config subnet pkt
      | Some DHCPREQUEST  -> input_request config subnet pkt
      | Some DHCPDECLINE  -> input_decline config subnet pkt
      | Some DHCPRELEASE  -> input_release config subnet pkt
      | Some DHCPINFORM   -> input_inform config subnet pkt
      | None -> Log.warn "Got malformed packet: no dhcp msgtype"
      | Some m -> Log.debug "Unhandled msgtype %s" (string_of_msgtype m)
  else
    Log.warn "Invalid packet %s" (string_of_pkt pkt)

let rec dhcp_recv config =
  let buffer = Dhcp.make_buf () in
  lwt (n, ifid) = Util.lwt_cstruct_recvif config.Config.recv_socket buffer in
  Log.debug "dhcp sock read %d bytes on interface %s" n (Util.if_indextoname ifid);
  if n = 0 then
    failwith "Unexpected EOF in DHCPD socket";
  (* Input the packet *)
  let () = match (Dhcp.pkt_of_buf buffer n) with
    | exception Invalid_argument e ->
      Log.warn "Dropped packet: %s" e
    | pkt ->
      Log.debug "valid packet from %d bytes" n;
      try input_pkt config ifid pkt
      with Invalid_argument e -> Log.warn "Input pkt %s" e
  in
  dhcp_recv config

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
  let () = config_log verbosity in
  let () = Log.debug "Using configuration file: %s" configfile in
  let () = Log.notice "Haesbaert DHCPD started" in
  let config = Config_parser.parse ~path:configfile () in
  let () = go_safe () in
  let recv_thread = dhcp_recv config in
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
