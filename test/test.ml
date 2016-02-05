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

let t_simple_config () =
  let config = make_simple_config ~options:[] in
  assert ((List.length config.Config.options) = 1);

  let config = make_simple_config ~options:[Routers [ip_t; ip2_t]; ] in
  assert ((List.length config.Config.options) = 2);
  match List.hd config.Config.options with
  | Subnet_mask _ -> ()
  | _ -> failwith "Subnet mask expected as first option"

let t_bad_simple_config () =
  let ok = try
      ignore @@ make_simple_config ~options:[
        Subnet_mask mask_t;
        Renewal_t1 Int32.max_int;
        End;
        Pad;
        Ip_lease_time Int32.max_int;
        Client_id (Id "chapolim");
      ];
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    failwith "Config succeeded, this is an error !"

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
      | Message_type _ -> ()
      | _ -> failwith "First option is not Message_type"
    in
    (* Check if the 3 lease timers are present. *)
    assert (List.exists (function Ip_lease_time _ -> true | _ -> false)
        reply.options);
    assert (List.exists (function Renewal_t1 _ -> true | _ -> false)
        reply.options);
    assert (List.exists (function Rebinding_t2 _ -> true | _ -> false)
        reply.options);
    (* Server identifier must be there. *)
    assert (List.exists (function Server_identifier _ -> true | _ -> false)
        reply.options);
    (* Check if both router options are present, and the order matches *)
    let routers = collect_routers reply.options in
    assert ((List.length routers) = 2);
    assert ((List.hd routers) = ip_t);
    if verbose then
        printf "%s\n%s\n%!" (yellow "<<OFFER>>") (pkt_to_string reply);
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
  (t_bad_simple_config, "bad simple config");
  (t_collect_replies, "collect replies");
  (t_discover, "discover->offer");
]

let _ =
  List.iter run_test all_tests;
