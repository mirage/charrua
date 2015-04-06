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

open Dhcp_cpkt

type op =
  | Bootrequest
  | Bootreply
  | Unknown

type htype =
  | Ethernet_10mb
  | Other

type flags =
  | Broadcast
  | Ignore

type chaddr =
  | Hwaddr of Macaddr.t
  | Cliid of Bytes.t

type dhcp_option =
  (* Start of section 3 of RFC 2132 *)
  | Subnet_mask of Ipaddr.V4.t              (* code 1 *)
  | Time_offset of Int32.t                  (* code 2 *)
  | Routers of Ipaddr.V4.t list             (* code 3 *)
  | Time_servers of Ipaddr.V4.t list        (* code 4 *)
  | Name_servers of Ipaddr.V4.t list        (* code 5 *)
  | Dns_servers of Ipaddr.V4.t list         (* code 6 *)
  | Log_servers of Ipaddr.V4.t list         (* code 7 *)
  | Cookie_servers of Ipaddr.V4.t list      (* code 8 *)
  | Lpr_servers of Ipaddr.V4.t list         (* code 9 *)
  | Impress_servers of Ipaddr.V4.t list     (* code 10 *)
  | Rsclocation_servers of Ipaddr.V4.t list (* code 11 *)
  | Hostname of string                      (* code 12 *)
  | Bootfile_size of int                    (* code 13 *)
  | Merit_dumpfile of string                (* code 14 *)
  | Domain_name of string                   (* code 15 *)
  | Swap_server of Ipaddr.V4.t              (* code 16 *)
  | Root_path of string                     (* code 17 *)
  (* Start of section 4 of RFC 2132 *)
  | Extension_path of string                (* code 18 *)
  | Ipforwarding of bool                    (* code 19 *)
  | Nlsr of bool                            (* code 20 *)
  | Policy_filters of (Ipaddr.V4.t * Ipaddr.V4.t) list (* code 21 *)
  | Max_datagram of int                     (* code 22 *)
  | Default_ip_ttl of int                   (* code 23 *)
  | Pmtu_aging_timo of Int32.t              (* code 24 *)
  | Pmtu_plateau_table of int list          (* code 25 *)
  (* Start of section 5 of RFC 2132 *)
  | Interface_mtu of int                    (* code 26 *)
  | All_subnets_local of bool               (* code 27 *)
  | Broadcast_addr of Ipaddr.V4.t           (* code 28 *)
  | Perform_mask_discovery of bool          (* code 29 *)
  | Mask_supplier of bool                   (* code 30 *)
  | Perform_router_disc of bool             (* code 31 *)
  | Router_sol_addr of Ipaddr.V4.t          (* code 32 *)
  | Static_routes of (Ipaddr.V4.t * Ipaddr.V4.t) list (* code 33 *)
  (* Start of section 6 of RFC 2132 *)
  | Unknown

type pkt = {
  op      : op;
  htype   : htype;
  hlen    : int;
  hops    : int;
  xid     : int32;
  secs    : int;
  flags   : flags;
  ciaddr  : Ipaddr.V4.t;
  yiaddr  : Ipaddr.V4.t;
  siaddr  : Ipaddr.V4.t;
  giaddr  : Ipaddr.V4.t;
  chaddr  : chaddr;
  sname   : string;
  file    : string;
  options : dhcp_option list;
}

let pkt_min_len = 236

(* 10KB, maybe there is an asshole doing insane stuff with Jumbo Frames *)
let make_buf () = Cstruct.create (1024 * 10) 
let op_of_buf buf = match get_cpkt_op buf with
  | 1 -> Bootrequest
  | 2 -> Bootreply
  | _ -> Unknown

let htype_of_buf buf = match get_cpkt_htype buf with
  | 1 -> Ethernet_10mb
  | _ -> Other

let hlen_of_buf = get_cpkt_hlen
let hops_of_buf = get_cpkt_hops
let xid_of_buf = get_cpkt_xid
let secs_of_buf = get_cpkt_secs

(* XXX this is implying policy instead of mechanism *)
let flags_of_buf buf =
  if ((get_cpkt_flags buf) land 0x8000) <> 0 then
    Broadcast
  else
    Ignore

let ciaddr_of_buf buf = Ipaddr.V4.of_int32 (get_cpkt_ciaddr buf)
let yiaddr_of_buf buf = Ipaddr.V4.of_int32 (get_cpkt_yiaddr buf)
let siaddr_of_buf buf = Ipaddr.V4.of_int32 (get_cpkt_siaddr buf)
let giaddr_of_buf buf = Ipaddr.V4.of_int32 (get_cpkt_giaddr buf)
let chaddr_of_buf buf htype hlen =
  let s = copy_cpkt_chaddr buf in
  if htype = Ethernet_10mb && hlen = 6 then
    Hwaddr (Macaddr.of_bytes_exn (Bytes.sub_string s 0 6))
  else
    Cliid (copy_cpkt_chaddr buf)

let sname_of_buf buf = copy_cpkt_sname buf
let file_of_buf buf = copy_cpkt_file buf

let options_of_buf buf buf_len =
  let rec loop buf options =
    let code = Cstruct.get_uint8 buf 0 in
    let () = Log.debug "saw option code %u" code in
    let len = Cstruct.get_uint8 buf 1 in
    let body = Cstruct.shift buf 2 in
    let bad_len = Printf.sprintf "Malformed len %d in option %d" len code in
    (* discard discards the option from the resulting list *)
    let discard () = loop (Cstruct.shift body len) options in
    (* take includes the option in the resulting list *)
    let take op = loop (Cstruct.shift body len) (op :: options) in
    let get_8 () = if len <> 1 then invalid_arg bad_len else
        Cstruct.get_uint8 body 0 in
    let get_bool () = match (get_8 ()) with
      | 1 -> true
      | 0 -> false
      | v -> invalid_arg ("invalid value for bool: " ^ string_of_int v)
    in
    let get_16 () = if len <> 2 then invalid_arg bad_len else
        Cstruct.BE.get_uint16 body 0 in
    let get_32 () = if len <> 4 then invalid_arg bad_len else
        Cstruct.BE.get_uint32 body 0 in
    let get_ip () = if len <> 4 then invalid_arg bad_len else
        Ipaddr.V4.of_int32 (get_32 ()) in
    let get_16_list () =
      let rec loop offset shorts =
        if offset = len then shorts else
          let short = Cstruct.BE.get_uint16 body 0 in
          loop ((succ offset) * 2) (short :: shorts)
      in
      if ((len mod 2) <> 0) || len <= 0 then invalid_arg bad_len else
        loop 0 []
    in
    (* Fetch ipv4s from options *)
    let get_ip_list () =
      let rec loop offset ips =
        if offset = len then ips else
          let word = Cstruct.BE.get_uint32 body offset in
          let ip = Ipaddr.V4.of_int32 word in
          loop ((succ offset) * 4) (ip :: ips)
      in
      if ((len mod 4) <> 0) || len <= 0 then invalid_arg bad_len else
        loop 0 []
    in
    (* Get a list of ip pairs *)
    let get_ip_pair_list () =
      let rec loop offset ips_ips =
        if offset = len then
          ips_ips
        else
          let word1 = Cstruct.BE.get_uint32 body offset in
          let ip1 = Ipaddr.V4.of_int32 word1 in
          let word2 = Cstruct.BE.get_uint32 body (offset + 4) in
          let ip2 = Ipaddr.V4.of_int32 word2 in
          loop ((succ offset) * 8) ((ip1, ip2) :: ips_ips)
      in
      if ((len mod 8) <> 0) || len <= 0 then
        invalid_arg bad_len
      else
        loop 0 []
    in
    let get_string () =  if len < 1 then invalid_arg bad_len else
        Cstruct.copy body 0 len
    in
    match code with
    (* Start of section 3 of RFC 2132 *)
    | 1 ->   take (Subnet_mask (get_ip ()))                (* Subnet Mask *)
    | 2 ->   take (Time_offset (get_32 ()))                (* Time Offset *)
    | 3 ->   take (Routers (get_ip_list ()))               (* Routers *)
    | 4 ->   take (Time_servers (get_ip_list ()))          (* Time servers *)
    | 5 ->   take (Name_servers (get_ip_list ()))          (* Name servers *)
    | 6 ->   take (Dns_servers (get_ip_list ()))           (* Domain name servers *)
    | 7 ->   take (Log_servers (get_ip_list ()))           (* Log servers *)
    | 8 ->   take (Cookie_servers (get_ip_list ()))        (* Cookie servers *)
    | 9 ->   take (Lpr_servers (get_ip_list ()))           (* Lpr servers *)
    | 10 ->  take (Impress_servers (get_ip_list ()))       (* Impress servers *)
    | 11 ->  take (Rsclocation_servers (get_ip_list ()))   (* Resource location servers *)
    | 12 ->  take (Hostname (get_string ()))               (* Hostname *)
    | 13 ->  take (Bootfile_size (get_16 ()))              (* Bootfile size *)
    | 14 ->  take (Merit_dumpfile (get_string ()))         (* Merit_dumpfile *)
    | 15 ->  take (Domain_name (get_string ()))            (* Domain name *)
    | 16 ->  take (Swap_server (get_ip ()))                (* Swap server *)
    | 17 ->  take (Root_path (get_string ()))              (* Root path *)
    | 18 ->  take (Extension_path (get_string ()))         (* Extension path *)
    (* Start of section 4 of RFC 2132 *)
    | 19 ->  take (Ipforwarding (get_bool ()))             (* Ipforwarding *)
    | 20 ->  take (Nlsr (get_bool ()))                     (* Non-local src routing *)
    | 21 ->  take (Policy_filters (get_ip_pair_list ()))   (* Policy filters *)
    | 22 ->  take (Max_datagram (get_16 ()))               (* Maximum datagram *)
    | 23 ->  take (Default_ip_ttl (get_8 ()))              (* Default ip ttl *)
    | 24 ->  take (Pmtu_aging_timo (get_32 ()))            (* Pmtu aging timeout *)
    | 25 ->  take (Pmtu_plateau_table (get_16_list ()))    (* Path mtu plateu table *)
    (* Start of section 5 of RFC 2132 *)
    | 26 ->  take (Interface_mtu (get_16 ()))              (* Interface mtu *)
    | 27 ->  take (All_subnets_local (get_bool ()))        (* All subnets are local *)
    | 28 ->  take (Broadcast_addr (get_ip ()))             (* Broadcast address *)
    | 29 ->  take (Perform_mask_discovery (get_bool ()))   (* Perform mask discovery *)
    | 30 ->  take (Mask_supplier (get_bool ()))            (* Mask supplier *)
    | 31 ->  take (Perform_router_disc (get_bool ()))      (* Perform router discovery *)
    | 32 ->  take (Router_sol_addr (get_ip ()))            (* Router solicitation addr *)
    | 33 ->  take (Static_routes (get_ip_pair_list ()))    (* Static routes table *)
    | 255 -> options            (* End of option list *)
    (* Start of section 6 of RFC 2132 *)
    | code ->
      Log.warn "Unknown option code %d" code;
      discard ()
  in
  (* Handle a pkt with no options *)
  if buf_len = pkt_min_len then
    []
  else
    (* Look for magic cookie *)
    let cookie = Cstruct.BE.get_uint32 buf pkt_min_len in
    if cookie <> 0x63825363l then
      invalid_arg "Invalid cookie";
    (* Jump over cookie and start options *)
    loop (Cstruct.shift buf (pkt_min_len + 4)) []

(* Raises invalid_arg if packet is malformed *)
let pkt_of_buf buf len =
  if len < pkt_min_len then
    invalid_arg (Printf.sprintf "packet too small %d < %d" len pkt_min_len);
  let op = op_of_buf buf in
  let htype = htype_of_buf buf in
  let hlen = hlen_of_buf buf in
  let hops = hops_of_buf buf in
  let xid = xid_of_buf buf in
  let secs = secs_of_buf buf in
  let flags = flags_of_buf buf in
  let ciaddr = ciaddr_of_buf buf in
  let yiaddr = yiaddr_of_buf buf in
  let siaddr = siaddr_of_buf buf in
  let giaddr = giaddr_of_buf buf in
  let chaddr = chaddr_of_buf buf htype hlen in
  let sname = sname_of_buf buf in
  let file = file_of_buf buf in
  let options = options_of_buf buf len in
  { op; htype; hlen; hops; xid; secs; flags; ciaddr; yiaddr;
    siaddr; giaddr; chaddr; sname; file; options }

(* str_of_* functions *)
let str_of_op = function
  | Bootrequest -> "Bootrequest"
  | Bootreply -> "Bootreply"
  | Unknown -> "Unknown"
let str_of_htype = function
  | Ethernet_10mb -> "Ethernet_10mb"
  | Other -> "Other"
let str_of_hlen = string_of_int
let str_of_hops = string_of_int
let str_of_xid xid = Printf.sprintf "0x%lx" xid
let str_of_secs = string_of_int
let str_of_flags = function
  | Broadcast -> "Broadcast"
  | Ignore -> "Ignore"
let str_of_ciaddr = Ipaddr.V4.to_string
let str_of_yiaddr = Ipaddr.V4.to_string
let str_of_siaddr = Ipaddr.V4.to_string
let str_of_giaddr = Ipaddr.V4.to_string
let str_of_chaddr = function
  | Hwaddr hwaddr -> Macaddr.to_string hwaddr
  | Cliid id -> "some id"       (* XXX finish me *)
let str_of_sname sname = sname
let str_of_file file = file
let str_of_options options = string_of_int  (List.length options)

let str_of_pkt pkt =
  Printf.sprintf "op: %s htype: %s hlen: %s hops: %s xid: %s secs: %s \
                  flags: %s ciaddr: %s yiaddr: %s siaddr: %s giaddr: %s \
                  chaddr: %s sname: %s file: %s options: %s"
    (str_of_op pkt.op) (str_of_htype pkt.htype) (str_of_hlen pkt.hlen)
    (str_of_hops pkt.hops) (str_of_xid pkt.xid) (str_of_secs pkt.secs)
    (str_of_flags pkt.flags) (str_of_ciaddr pkt.ciaddr)
    (str_of_yiaddr pkt.yiaddr) (str_of_siaddr pkt.siaddr)
    (str_of_giaddr pkt.giaddr) (str_of_chaddr pkt.chaddr)
    (str_of_sname pkt.sname) (str_of_file pkt.file) (str_of_options pkt.options)
