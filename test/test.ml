(*
 * Copyright (c) 2015 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 * Copyright (c) 2016 Gina Marie Maini <gina@beancode.io>
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

let printf = Printf.printf

let verbose = (Array.length Sys.argv) = 2 && Sys.argv.(1) = "-v"

let tty_out = Unix.isatty Unix.stdout
let colored_or_not cfmt fmt =
  if tty_out then (Printf.sprintf cfmt) else (Printf.sprintf fmt)
let red fmt    = colored_or_not ("\027[31m"^^fmt^^"\027[m") fmt
let green fmt  = colored_or_not ("\027[32m"^^fmt^^"\027[m") fmt
let yellow fmt = colored_or_not ("\027[33m"^^fmt^^"\027[m") fmt
let blue fmt   = colored_or_not ("\027[36m"^^fmt^^"\027[m") fmt

let ip_t = Ipaddr.V4.of_string_exn "192.168.1.1"
let ip2_t = Ipaddr.V4.of_string_exn "192.168.1.2"
let ip3_t = Ipaddr.V4.of_string_exn "192.168.1.3"
let ip55_t = Ipaddr.V4.of_string_exn "192.168.1.55"
let mac_t = Macaddr.of_string_exn "aa:aa:aa:aa:aa:aa"
let mac2_t = Macaddr.of_string_exn "bb:bb:bb:bb:bb:bb"
let mask_t = Ipaddr.V4.of_string_exn "255.255.255.0"
let range_t = (Ipaddr.V4.of_string_exn "192.168.1.50",
               Ipaddr.V4.of_string_exn "192.168.1.100")

open Dhcp_wire
open Dhcp_server

let t_option_codes () =
  (* Make sure parameters 0-255 are there. *)
  for i = 0 to 255 do
    ignore (int_to_option_code_exn i)
  done

let make_simple_config =
  Config.make
    ~hostname:"Duder DHCP server!"
    ~default_lease_time:(60 * 60 * 1)
    ~max_lease_time:(60 * 60 * 10)
    ~hosts:[]
    ~addr_tuple:(ip_t, mac_t)
    ~network:(Ipaddr.V4.Prefix.make 24 ip_t)
    ~range:range_t

(* Check if 3 lease timers are present and are what we expect. *)
let assert_timers options =
  let () = match find_ip_lease_time options with
    | None -> failwith "no Ip_lease_time found"
    | Some x -> assert (x = Int32.of_int 3600)
  in
  let () = match find_renewal_t1 options with
    | None -> failwith "no Renewal_t1 found"
    | Some x -> assert (x = Int32.of_int 1800)
  in
  match find_rebinding_t2 options with
  | None -> failwith "no Rebinding_t2 found"
  | Some x -> assert (x = Int32.of_int 2880)

let t_simple_config () =
  let config = make_simple_config ~options:[] in
  assert ((List.length config.Config.options) = 1);

  let config = make_simple_config ~options:[Routers [ip_t; ip2_t]; ] in
  assert ((List.length config.Config.options) = 2);
  match List.hd config.Config.options with
  | Subnet_mask _ -> ()
  | _ -> failwith "Subnet mask expected as first option"

let t_renewal_time_inoptions () =
  let ok = try
      ignore @@ make_simple_config
        ~options:[Renewal_t1 Int32.max_int];
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    failwith "user cannot request renewal via options"

let t_bad_junk_padding_config () =
  let ok = try
      ignore @@ make_simple_config ~options:[
        Subnet_mask mask_t;
        End; (* Should not allow end in configuration *)
        Pad; (* Should not allow pad in configuration *)
        Client_id (Id "The dude");
      ];
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    failwith "can't insert padding and random numbers via options"

let t_ip_lease_time_inoptions () =
  let ok = try
      ignore @@ make_simple_config
        ~options:[Ip_lease_time Int32.max_int];
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    failwith "can't request ip lease time via options"

let t_collect_replies () =
  let config = make_simple_config
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "wololo";
                Url "url";
                Pop3_servers [ip_t; ip2_t];
                Max_message 1200]
  in
  let requests = [DNS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
                  POP3_SERVERS; SUBNET_MASK; MAX_MESSAGE; RENEWAL_T1]
  in
  (* RENEWAL_T1 is ignored, so replies length should be - 1 *)
  let replies = Input.collect_replies_test config requests in
  assert ((List.length replies) = ((List.length requests) - 1));
  let () = match List.hd replies with
    | Subnet_mask _ -> ()
    | _ -> failwith "Subnet mask expected as first option"
  in
  assert ((List.length replies) = (List.length requests) - 1);
  let () = match List.hd @@ List.rev replies with
    | Url _ -> ()
    | _ -> failwith "Url expected to be last"
  in
  assert ((collect_routers replies) = [ip_t; ip2_t])

let t_discover () =
  let config = make_simple_config
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "Shut up Donnie !";
                Url "Fucking Quintana man, that creep can roll...";
                Pop3_servers [ip_t; ip2_t];
                Time_servers [ip_t];
               ]
  in
  let discover = {
    srcmac = mac2_t;
    dstmac = mac_t;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = client_port;
    dstport = server_port;
    op = BOOTREQUEST;
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = Int32.of_int 0xabacabb;
    secs = 0;
    flags = Unicast;
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = mac_t;
    sname = Bytes.empty;
    file = Bytes.empty;
    options = [
      Message_type DHCPDISCOVER;
      Client_id (Id "W.Sobchak");
      Parameter_requests [
        DNS_SERVERS; NIS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
        POP3_SERVERS; SUBNET_MASK; DEFAULT_IP_TTL;
        NETWARE_IP_DOMAIN; ARP_CACHE_TIMO
      ]
    ]
  }
  in
  if verbose then
    printf "\n%s\n%s\n%!" (yellow "<<DISCOVER>>") (pkt_to_string discover);
  match Input.input_pkt config (Lease.make_db ()) discover (Unix.time ()) with
  | Input.Reply (reply, db) ->
    assert (db = (Lease.make_db ()));
    assert (reply.srcmac = mac_t);
    assert (reply.dstmac = mac2_t);
    assert (reply.srcip = ip_t);
    assert (reply.dstip <> ip_t);
    assert (reply.dstip <> ip2_t);
    assert (reply.dstip <> Ipaddr.V4.any);
    assert (reply.srcport = server_port);
    assert (reply.dstport = client_port);
    assert (reply.op = BOOTREPLY);
    assert (reply.htype = Ethernet_10mb);
    assert (reply.hlen = 6);
    assert (reply.hops = 0);
    assert (reply.xid = Int32.of_int 0xabacabb);
    assert (reply.secs = 0);
    assert (reply.flags = Unicast);
    assert (reply.ciaddr = Ipaddr.V4.any);
    assert (reply.yiaddr <> Ipaddr.V4.any);
    assert (reply.yiaddr = reply.dstip);
    assert (Util.addr_in_range reply.yiaddr range_t);
    assert (reply.siaddr = ip_t);
    assert (reply.giaddr = Ipaddr.V4.any);
    assert (reply.sname = "Duder DHCP server!");
    assert (reply.file = Bytes.empty);
    (* 5 options are included regardless of parameter requests. *)
    assert ((List.length reply.options) = (5 + 6));
    let () = match List.hd reply.options with
      | Message_type x -> assert (x = DHCPOFFER);
      | _ -> failwith "First option is not Message_type"
    in
    assert_timers reply.options;
    (* Check if both router options are present, and the order matches *)
    let routers = collect_routers reply.options in
    assert ((List.length routers) = 2);
    assert ((List.hd routers) = ip_t);
    if verbose then
      printf "%s\n%s\n%!" (yellow "<<OFFER>>") (pkt_to_string reply);
  | _ -> failwith "No reply"

let t_bad_discover () =
  let config = make_simple_config
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "The Dude";
                Url "New shit has come to light, man.";
                Pop3_servers [ip_t; ip2_t];
                Time_servers [ip_t];
               ]
  in
  let bad_discover = {
    srcmac = mac2_t;
    dstmac = Macaddr.of_string_exn "cc:cc:cc:cc:cc:cc";
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = client_port;
    dstport = server_port;
    op = BOOTREQUEST;
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = Int32.of_int 0xabacabb;
    secs = 0;
    flags = Unicast;
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = mac_t;
    sname = Bytes.empty;
    file = Bytes.empty;
    options = [
      Message_type DHCPDISCOVER;
      Client_id (Id "W.Sobchak");
      Parameter_requests [
        DNS_SERVERS; NIS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
        POP3_SERVERS; SUBNET_MASK; DEFAULT_IP_TTL;
        NETWARE_IP_DOMAIN; ARP_CACHE_TIMO
      ]
    ]
  }
  in
  match Input.input_pkt config (Lease.make_db ()) bad_discover (Unix.time ()) with
  | Input.Silence -> ()
  | _ -> failwith "This packet was not for us, should be Silence"

let t_request () =
  let now = Unix.time () in
  let config = make_simple_config
      ~options:[Routers [ip_t; ip2_t];
                Dns_servers [ip_t];
                Domain_name "Shut up Donnie !";
                Url "Fucking Quintana man, that creep can roll...";
                Pop3_servers [ip_t; ip2_t];
                Time_servers [ip_t];
               ]
  in
  let request = {
    srcmac = mac2_t;
    dstmac = mac_t;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = client_port;
    dstport = server_port;
    op = BOOTREQUEST;
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = Int32.of_int 0xabacabb;
    secs = 0;
    flags = Broadcast;          (* Request a broadcast answer *)
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = mac_t;
    sname = Bytes.empty;
    file = Bytes.empty;
    options = [
      Message_type DHCPREQUEST;
      Client_id (Id "W.Sobchak");
      Parameter_requests [
        DNS_SERVERS; NIS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
        POP3_SERVERS; SUBNET_MASK; DEFAULT_IP_TTL;
        NETWARE_IP_DOMAIN; ARP_CACHE_TIMO
      ];
      Request_ip ip55_t;
      Server_identifier ip_t;
    ]
  }
  in
  if verbose then
    printf "\n%s\n%s\n%!" (yellow "<<REQUEST>>") (pkt_to_string request);
  let db =
    match Input.input_pkt config (Lease.make_db ()) request now with
    | Input.Reply (reply, db) ->
      (* Check if our new lease is there *)
      assert (db <> (Lease.make_db ()));
      let () =
        match Lease.lease_of_client_id (Id "W.Sobchak") db with
        | None -> failwith "Lease not found";
        | Some l ->
          let open Dhcp_server.Lease in
          assert (l.client_id = (Id "W.Sobchak"));
          assert (not (expired l now));
          assert (l.tm_start <= (Int32.of_float now));
          assert (l.tm_end >= (Int32.of_float now));
          assert ((Lease.timeleft l now) <= (Int32.of_int 3600));
          assert ((Lease.timeleft l now) >= (Int32.of_int 3599));
      in
      assert (reply.srcmac = mac_t);
      assert (reply.dstmac = Macaddr.broadcast);
      assert (reply.srcip = ip_t);
      assert (reply.dstip = Ipaddr.V4.broadcast);
      assert (reply.srcport = server_port);
      assert (reply.dstport = client_port);
      assert (reply.op = BOOTREPLY);
      assert (reply.htype = Ethernet_10mb);
      assert (reply.hlen = 6);
      assert (reply.hops = 0);
      assert (reply.xid = Int32.of_int 0xabacabb);
      assert (reply.secs = 0);
      assert (reply.flags = Broadcast); (* Not required by RFC2131 section 4.1 *)
      assert (reply.ciaddr = Ipaddr.V4.any);
      assert (reply.yiaddr <> Ipaddr.V4.any);
      assert (Util.addr_in_range reply.yiaddr range_t);
      assert (reply.siaddr = ip_t);
      assert (reply.giaddr = Ipaddr.V4.any);
      assert (reply.sname = "Duder DHCP server!");
      assert (reply.file = Bytes.empty);
      (* 5 options are included regardless of parameter requests. *)
      assert ((List.length reply.options) = (5 + 6));
      let () = match List.hd reply.options with
        | Message_type x -> assert (x = DHCPACK);
        | _ -> failwith "First option is not Message_type"
      in
      assert_timers reply.options;
      (* Server identifier must be there. *)
      assert (List.exists (function Server_identifier _ -> true | _ -> false)
          reply.options);
      (* Check if both router options are present, and the order matches *)
      let routers = collect_routers reply.options in
      assert ((List.length routers) = 2);
      assert ((List.hd routers) = ip_t);
      if verbose then
        printf "%s\n%s\n%!" (yellow "<<ACK>>") (pkt_to_string reply);
      db
    | _ -> failwith "No reply"
  in

  (* Build a second request from a different client, we should get a NAK. *)

  let request = {
    srcmac = mac2_t;
    dstmac = mac_t;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = client_port;
    dstport = server_port;
    op = BOOTREQUEST;
    htype = Ethernet_10mb;
    hlen = 6;
    hops = 0;
    xid = Int32.of_int 0xabacabb;
    secs = 0;
    flags = Broadcast;          (* Request a broadcast answer *)
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = mac_t;
    sname = Bytes.empty;
    file = Bytes.empty;
    options = [
      Message_type DHCPREQUEST;
      Client_id (Id "The Dude");
      Parameter_requests [
        DNS_SERVERS; NIS_SERVERS; ROUTERS; DOMAIN_NAME; URL;
        POP3_SERVERS; SUBNET_MASK; DEFAULT_IP_TTL;
        NETWARE_IP_DOMAIN; ARP_CACHE_TIMO
      ];
      Request_ip ip55_t;
      Server_identifier ip_t;
    ]
  }
  in
  match Input.input_pkt config db request now with
  | Input.Reply (reply, odb) ->
    assert (db = odb);
    assert ((List.length reply.options) = 4);
    let () = match List.hd reply.options with
      | Message_type x -> assert (x = DHCPNAK);
      | _ -> failwith "First option is not Message_type"
    in
    if verbose then
      printf "%s\n%s\n%!" (yellow "<<NAK>>") (pkt_to_string reply);
  | _ -> failwith "No reply"

let run_test test =
  let f = fst test in
  let name = snd test in
  printf "%s %-27s%!" (blue "%s" "Test") (yellow "%s" name);
  let () = try f () with
      exn -> printf "%s\n%!" (red "failed");
      raise exn
  in
  printf "%s\n%!" (green "ok")

let all_tests = [
  (t_option_codes, "option codes");
  (Pcap.t_pcap, "pcap");
  (t_simple_config, "simple config");
  (t_renewal_time_inoptions, "renewal_t in opts");
  (t_bad_junk_padding_config, "padding in opts");
  (t_ip_lease_time_inoptions, "lease time in opts");
  (t_collect_replies, "collect replies");
  (t_discover, "discover->offer");
  (t_bad_discover, "wrong mac address");
  (t_request, "request->ack/nak");
]

let _ =
  List.iter run_test all_tests;
