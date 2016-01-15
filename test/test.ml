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

let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m")

let ip_t = Ipaddr.V4.of_string_exn "192.168.1.1"
let ip2_t = Ipaddr.V4.of_string_exn "192.168.1.2"
let mac_t = Macaddr.of_string_exn "aa:bb:cc:dd:ee:00"
let mask_t = Ipaddr.V4.of_string_exn "255.255.255.0"
let range_t = (ip_t, Ipaddr.V4.of_string_exn "192.168.1.100")

open Dhcp_wire
open Dhcp_server

let t_option_codes () =
    (* Make sure parameters 0-255 are there. *)
  for i = 0 to 255 do
      ignore (int_to_option_code_exn i)
  done

let make_simple_config =
  Config.make
    ~hostname:"Tests are awesome!"
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

let run_test test =
  let f = fst test in
  let name = snd test in
  Printf.printf "%s %-27s%!" (blue "%s" "Test") (yellow "%s" name);
  let () = try f () with
      exn -> Printf.printf "%s\n%!" (red "failed");
      raise exn
  in
  Printf.printf "%s\n%!" (green "ok")

let all_tests = [
  (t_option_codes, "option codes");
  (Pcap.t_pcap, "pcap");
  (t_simple_config, "simple config");
  (t_bad_simple_config, "bad simple config");
  (t_collect_replies, "collect replies");
]

let _ =
  List.iter run_test all_tests;
