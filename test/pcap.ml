(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
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

(*type pcap_header = {
  magic_number:  uint32_t;  (* magic number *)
  version_major: uint16_t;  (* major version number *)
  version_minor: uint16_t;  (* minor version number *)
  thiszone:      uint32_t;  (* GMT to local correction *)
  sigfigs:       uint32_t;  (* accuracy of timestamps *)
  snaplen:       uint32_t;  (* max length of captured packets, in octets *)
  network:       uint32_t;  (* data link type *)
  } *)

let get_pcap_header_magic_number cs =
  String.get_int32_le cs 0

let get_pcap_header_version_major cs =
  String.get_uint16_le cs 4

let get_pcap_header_version_minor cs =
  String.get_uint16_le cs 6

let get_pcap_header_thiszone cs =
  String.get_int32_le cs 8

let get_pcap_header_sigfigs cs =
  String.get_int32_le cs 12

let get_pcap_header_snaplen cs =
  String.get_int32_le cs 16

let get_pcap_header_network cs =
  String.get_int32_le cs 20

let sizeof_pcap_header = 24

(* type pcap_packet = {
  ts_sec:  uint32_t;  (* timestamp seconds *)
  ts_usec:  uint32_t; (* timestamp microseconds *)
  incl_len: uint32_t; (* number of octets of packet saved in file *)
  orig_len: uint32_t; (* actual length of packet *)
   } *)

let get_pcap_packet_ts_sec cs =
  String.get_int32_le cs 0

let get_pcap_packet_ts_usec cs =
  String.get_int32_le cs 4

let get_pcap_packet_incl_len cs =
  String.get_int32_le cs 8

let get_pcap_packet_orig_len cs =
  String.get_int32_le cs 12

let sizeof_pcap_packet = 16

let test_packet p len =
  match (Dhcp_wire.pkt_of_buf p len) with
  | Error `Msg e -> failwith e
  | Error `Not_dhcp -> failwith "Not a DHCP message"
  | Ok pkt ->
    if verbose then
      Format.printf "DHCP: %a\n%!" Dhcp_wire.pp_pkt pkt;
    let buf = Dhcp_wire.buf_of_pkt pkt in
    match (Dhcp_wire.pkt_of_buf buf len) with
    | Error `Msg e -> failwith e
    | Error `Not_dhcp -> failwith "Not a DHCP message"
    | Ok pkt2 ->
      if pkt2 <> pkt then begin
        printf "buffers differ !\n";
        Format.printf "pcap buf:@.%a@." (Ohex.pp_hexdump ()) p;
        Format.printf "our buf:@.%a@." (Ohex.pp_hexdump ()) buf;
        Format.printf "generated pkt:\n%a\n" Dhcp_wire.pp_pkt pkt2;
        failwith "Serialization bug found !"
  end

let test_pcap_packet (hdr, pkt) =
  let ts_sec = get_pcap_packet_ts_sec hdr in
  let ts_usec = get_pcap_packet_ts_usec hdr in
  let incl_len = get_pcap_packet_incl_len hdr in
  let orig_len = get_pcap_packet_orig_len hdr in
  if verbose then
    printf "***** %lu.%lu  bytes %lu (of %lu)\n%!"
      ts_sec ts_usec incl_len orig_len;
  test_packet pkt (Int32.to_int incl_len)

let test_pcap_header buf =
  let magic = get_pcap_header_magic_number buf in
  let endian =
    match magic with
    |0xa1b2c3d4l -> "bigendian"
    |0xd4c3b2a1l -> "littlendian"
    |_ -> "not a pcap file"
  in
  let version_major = get_pcap_header_version_major buf in
  let version_minor = get_pcap_header_version_minor buf in
  let thiszone = get_pcap_header_thiszone buf in
  let sigfis = get_pcap_header_sigfigs buf in
  let snaplen = get_pcap_header_snaplen buf in
  let header_network = get_pcap_header_network buf in
  if verbose then begin
    printf "pcap_header (len %d)\n%!" sizeof_pcap_header;
    printf "magic_number %lx (%s)\n%!" magic endian;
    printf "version %d %d\n%!" version_major version_minor;
    printf "timezone shift %lu\n%!" thiszone;
    printf "timestamp accuracy %lu\n%!" sigfis;
    printf "snaplen %lu\n%!" snaplen;
    printf "lltype %lx\n%!" header_network
  end

let mmap file =
  let ic = open_in file in
  let ln = in_channel_length ic in
  let rs = Bytes.create ln in
  really_input ic rs 0 ln;
  close_in ic;
  Bytes.unsafe_to_string rs

let parse file =
  if verbose then
    printf "parsing %s\n%!" file;
  let t = mmap file in
  if verbose then
    printf "total pcap file length %d\n%!" (String.length t);

  let header, body =
    String.sub t 0 sizeof_pcap_header,
    String.sub t sizeof_pcap_header (String.length t - sizeof_pcap_header)
  in
  if verbose then
      test_pcap_header header;

  let packets =
    let rec dec off acc =
      if String.length body = off then
        List.rev acc
      else
        let hdr = String.sub body off sizeof_pcap_packet in
        let len = Int32.to_int (get_pcap_packet_incl_len hdr) in
        let pkg = String.sub body (off + sizeof_pcap_packet) len in
        dec (off + len + sizeof_pcap_packet) ((hdr, pkg) :: acc)
    in
    dec 0 []
  in
  let num_packets = List.fold_left
      (fun a packet -> test_pcap_packet packet; (a+1))
      0 packets
  in
  if verbose then
    printf "%s had %d packets\n\n%!" file num_packets

let testfiles = ["dhcp.pcap"; "dhcp2.pcap" ]

let t_pcap () =
  List.iter parse testfiles
