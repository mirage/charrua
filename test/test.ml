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

let t_option_codes () =
    (* Make sure parameters 0-255 are there. *)
  for i = 0 to 255 do
      ignore (Dhcp_wire.int_to_option_code_exn i)
  done

let make_simple_config =
  let open Dhcp_server.Config in
  let ip = Ipaddr.V4.of_string_exn "192.168.1.1" in
  let mac = Macaddr.of_string_exn "aa:bb:cc:dd:ee:00" in
  let range = (ip, Ipaddr.V4.of_string_exn "192.168.1.100") in
  make
    ~hostname:"Tests are awesome!"
    ~default_lease_time:(60 * 60 * 1)
    ~max_lease_time:(60 * 60 * 10)
    ~hosts:[]
    ~addr_tuple:(ip, mac)
    ~network:(Ipaddr.V4.Prefix.make 24 ip)
    ~range:range

let t_simple_config () =
  ignore @@ make_simple_config ~options:[]

let t_bad_simple_config () =
  let ok = try
      ignore @@ make_simple_config ~options:[Dhcp_wire.End];
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    failwith "Config succeeded, this is an error !"

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
]

let _ =
  List.iter run_test all_tests;
