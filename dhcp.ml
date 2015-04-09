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
  | Extension_path of string                (* code 18 *)
  | Ipforwarding of bool                    (* code 19 *)
  | Nlsr of bool                            (* code 20 *)
  | Policy_filters of (Ipaddr.V4.t * Ipaddr.V4.t) list (* code 21 *)
  | Max_datagram of int                     (* code 22 *)
  | Default_ip_ttl of int                   (* code 23 *)
  | Pmtu_ageing_timo of Int32.t             (* code 24 *)
  | Pmtu_plateau_table of int list          (* code 25 *)
  | Interface_mtu of int                    (* code 26 *)
  | All_subnets_local of bool               (* code 27 *)
  | Broadcast_addr of Ipaddr.V4.t           (* code 28 *)
  | Perform_mask_discovery of bool          (* code 29 *)
  | Mask_supplier of bool                   (* code 30 *)
  | Perform_router_disc of bool             (* code 31 *)
  | Router_sol_addr of Ipaddr.V4.t          (* code 32 *)
  | Static_routes of (Ipaddr.V4.t * Ipaddr.V4.t) list (* code 33 *)
  | Trailer_encapsulation of bool           (* code 34 *)
  | Arp_cache_timo of Int32.t               (* code 35 *)
  | Ethernet_encapsulation of bool          (* code 36 *)
  | Tcp_default_ttl of int                  (* code 37 *)
  | Tcp_keepalive_interval of Int32.t       (* code 38 *)
  | Tcp_keepalive_garbage of int            (* code 39 *)
  | Nis_domain of string                    (* code 40 *)
  | Nis_servers of Ipaddr.V4.t list         (* code 41 *)
  | Ntp_servers of Ipaddr.V4.t list         (* code 42 *)
  | Vendor_specific of string               (* code 43 *)
  | Netbios_name_servers of Ipaddr.V4.t list(* code 44 *)
  | Netbios_datagram_distrib_servers of Ipaddr.V4.t list (* code 45 *)
  | Netbios_node of int                     (* code 46 *)
  | Netbios_scope of string                 (* code 47 *)
  | Xwindow_font_servers of Ipaddr.V4.t list(* code 48 *)
  | Xwindow_display_managers of Ipaddr.V4.t list (* code 49 *)
  | Request_ip of Ipaddr.V4.t               (* code 50 *)
  | Ip_lease_time of Int32.t                (* code 51 *)
  | Option_overload of int                  (* code 52 *)
  | Dhcp_message_type of int                (* code 53 *)
  | Server_identifier of Ipaddr.V4.t        (* code 54 *)
  | Parameter_requests of int list          (* code 55 *)
  | Message of string                       (* code 56 *)
  | Max_message of int                      (* code 57 *)
  | Renewal_t1 of Int32.t                   (* code 58 *)
  | Rebinding_t2 of Int32.t                 (* code 59 *)
  | Vendor_class_id of string               (* code 60 *)
  | Client_id of string                     (* code 61 *)
  | Nis_plus_domain of string               (* code 64 *)
  | Nis_plus_servers of Ipaddr.V4.t list    (* code 65 *)
  | Tftp_server_name of string              (* code 66 *)
  | Bootfile_name of string                 (* code 67 *)
  | Mobile_ip_home_agent of Ipaddr.V4.t list(* code 68 *)
  | Smtp_servers of Ipaddr.V4.t list        (* code 69 *)
  | Pop3_servers of Ipaddr.V4.t list        (* code 70 *)
  | Nntp_servers of Ipaddr.V4.t list        (* code 71 *)
  | Www_servers of Ipaddr.V4.t list         (* code 72 *)
  | Finger_servers of Ipaddr.V4.t list      (* code 73 *)
  | Irc_servers of Ipaddr.V4.t list         (* code 74 *)
  | Streettalk_servers of Ipaddr.V4.t list  (* code 75 *)
  | Streettalk_da of Ipaddr.V4.t list       (* code 76 *)
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
  let rec collect_options buf options =
    let code = Cstruct.get_uint8 buf 0 in
    let () = Log.debug "saw option code %u" code in
    let len = Cstruct.get_uint8 buf 1 in
    let body = Cstruct.shift buf 2 in
    let bad_len = Printf.sprintf "Malformed len %d in option %d" len code in
    (* discard discards the option from the resulting list *)
    let discard () = collect_options (Cstruct.shift body len) options in
    (* take includes the option in the resulting list *)
    let take op = collect_options (Cstruct.shift body len) (op :: options) in
    let get_8 () = if len <> 1 then invalid_arg bad_len else
        Cstruct.get_uint8 body 0 in
    let get_8_list () =
      let rec loop offset shorts =
        if offset = len then shorts else
          let short = Cstruct.get_uint8 body 0 in
          loop (succ offset) (short :: shorts)
      in
      if len <= 0 then invalid_arg bad_len else
        List.rev (loop 0 [])
    in
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
        List.rev (loop 0 [])
    in
    (* Fetch ipv4s from options *)
    let get_ip_list ?(min_len=4) () =
      let rec loop offset ips =
        if offset = len then ips else
          let word = Cstruct.BE.get_uint32 body offset in
          let ip = Ipaddr.V4.of_int32 word in
          loop ((succ offset) * 4) (ip :: ips)
      in
      if ((len mod 4) <> 0) || len < min_len then invalid_arg bad_len else
        List.rev (loop 0 [])
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
        List.rev (loop 0 [])
    in
    let get_string () =  if len < 1 then invalid_arg bad_len else
        Cstruct.copy body 0 len
    in
    match code with
    | 1 ->   take (Subnet_mask (get_ip ()))
    | 2 ->   take (Time_offset (get_32 ()))
    | 3 ->   take (Routers (get_ip_list ()))
    | 4 ->   take (Time_servers (get_ip_list ()))
    | 5 ->   take (Name_servers (get_ip_list ()))
    | 6 ->   take (Dns_servers (get_ip_list ()))
    | 7 ->   take (Log_servers (get_ip_list ()))
    | 8 ->   take (Cookie_servers (get_ip_list ()))
    | 9 ->   take (Lpr_servers (get_ip_list ()))
    | 10 ->  take (Impress_servers (get_ip_list ()))
    | 11 ->  take (Rsclocation_servers (get_ip_list ()))
    | 12 ->  take (Hostname (get_string ()))
    | 13 ->  take (Bootfile_size (get_16 ()))
    | 14 ->  take (Merit_dumpfile (get_string ()))
    | 15 ->  take (Domain_name (get_string ()))
    | 16 ->  take (Swap_server (get_ip ()))
    | 17 ->  take (Root_path (get_string ()))
    | 18 ->  take (Extension_path (get_string ()))
    | 19 ->  take (Ipforwarding (get_bool ()))
    | 20 ->  take (Nlsr (get_bool ()))
    | 21 ->  take (Policy_filters (get_ip_pair_list ()))
    | 22 ->  take (Max_datagram (get_16 ()))
    | 23 ->  take (Default_ip_ttl (get_8 ()))
    | 24 ->  take (Pmtu_ageing_timo (get_32 ()))
    | 25 ->  take (Pmtu_plateau_table (get_16_list ()))
    | 26 ->  take (Interface_mtu (get_16 ()))
    | 27 ->  take (All_subnets_local (get_bool ()))
    | 28 ->  take (Broadcast_addr (get_ip ()))
    | 29 ->  take (Perform_mask_discovery (get_bool ()))
    | 30 ->  take (Mask_supplier (get_bool ()))
    | 31 ->  take (Perform_router_disc (get_bool ()))
    | 32 ->  take (Router_sol_addr (get_ip ()))
    | 33 ->  take (Static_routes (get_ip_pair_list ()))
    | 34 ->  take (Trailer_encapsulation (get_bool ()))
    | 35 ->  take (Arp_cache_timo (get_32 ()))
    | 36 ->  take (Ethernet_encapsulation (get_bool ()))
    | 37 ->  take (Tcp_default_ttl (get_8 ()))
    | 38 ->  take (Tcp_keepalive_interval (get_32 ()))
    | 39 ->  take (Tcp_keepalive_garbage (get_8 ()))
    | 40 ->  take (Nis_domain (get_string ()))
    | 41 ->  take (Nis_servers (get_ip_list ()))
    | 42 ->  take (Ntp_servers (get_ip_list ()))
    | 43 ->  take (Vendor_specific (get_string ()))
    | 44 ->  take (Netbios_name_servers (get_ip_list ()))
    | 45 ->  take (Netbios_datagram_distrib_servers (get_ip_list ()))
    | 46 ->  take (Netbios_node (get_8 ()))
    | 47 ->  take (Netbios_scope (get_string ()))
    | 48 ->  take (Xwindow_font_servers (get_ip_list ()))
    | 49 ->  take (Xwindow_display_managers (get_ip_list ()))
    | 50 ->  take (Request_ip (get_ip ()))
    | 51 ->  take (Ip_lease_time (get_32 ()))
    | 52 ->  take (Option_overload (get_8 ()))
    | 53 ->  take (Dhcp_message_type (get_8 ()))
    | 54 ->  take (Server_identifier (get_ip ()))
    | 55 ->  take (Parameter_requests (get_8_list ()))
    | 56 ->  take (Message (get_string ()))
    | 57 ->  take (Max_message (get_16 ()))
    | 58 ->  take (Renewal_t1 (get_32 ()))
    | 59 ->  take (Rebinding_t2 (get_32 ()))
    | 60 ->  take (Vendor_class_id (get_string ()))
    | 61 ->  take (Client_id (get_string ()))
    | 64 ->  take (Nis_plus_domain (get_string ()))
    | 65 ->  take (Nis_plus_servers (get_ip_list ()))
    | 66 ->  take (Tftp_server_name (get_string ()))
    | 67 ->  take (Bootfile_name (get_string ()))
    | 68 ->  take (Mobile_ip_home_agent (get_ip_list ~min_len:0 ()))
    | 69 ->  take (Smtp_servers (get_ip_list ()))
    | 70 ->  take (Pop3_servers (get_ip_list ()))
    | 71 ->  take (Nntp_servers (get_ip_list ()))
    | 72 ->  take (Www_servers (get_ip_list ()))
    | 73 ->  take (Finger_servers (get_ip_list ()))
    | 74 ->  take (Irc_servers (get_ip_list ()))
    | 75 ->  take (Streettalk_servers (get_ip_list ()))
    | 76 ->  take (Streettalk_da (get_ip_list ()))
    | 255 -> options            (* End of option list *)
    | code ->
      Log.warn "Unknown option code %d" code;
      discard ()
  in
  (* Extends options if it finds an Option_overload *)
  let extend_options buf options =
    let rec search = function
      | [] -> None
      | opt :: tl -> match opt with
        | Option_overload v -> Some v
        | _ -> search tl
    in
    match search options with
    | None -> options           (* Nothing to do, identity function *)
    | Some v -> match v with
      | 1 -> collect_options (get_cpkt_file buf) options    (* It's in file *)
      | 2 -> collect_options (get_cpkt_sname buf) options   (* It's in sname *)
      | 3 -> collect_options (get_cpkt_file buf) options |> (* OMG both *)
             collect_options (get_cpkt_sname buf)
      | _ -> invalid_arg ("Invalid overload code: " ^ string_of_int v)
  in
  (* Handle a pkt with no options *)
  if buf_len = pkt_min_len then
    []
  else
    (* Look for magic cookie *)
    let cookie = Cstruct.BE.get_uint32 buf pkt_min_len in
    if cookie <> 0x63825363l then
      invalid_arg "Invalid cookie";
    let options_start = Cstruct.shift buf (pkt_min_len + 4) in
    (* Jump over cookie and start options, also extend them if necessary *)
    let options = collect_options options_start [] |>
                  extend_options buf in
    List.rev options


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
let str_of_option = function
  | Subnet_mask _                      -> "subnet_mask"
  | Time_offset _                      -> "time_offset"
  | Routers _                          -> "routers"
  | Time_servers _                     -> "time_servers"
  | Name_servers _                     -> "name_servers"
  | Dns_servers _                      -> "dns_servers"
  | Log_servers _                      -> "log_servers"
  | Cookie_servers _                   -> "cookie_servers"
  | Lpr_servers _                      -> "lpr_servers"
  | Impress_servers _                  -> "impress_servers"
  | Rsclocation_servers _              -> "resource_relocation_servers"
  | Hostname _                         -> "hostname"
  | Bootfile_size _                    -> "bootfile_size"
  | Merit_dumpfile _                   -> "merit_dump_file"
  | Domain_name _                      -> "domain_name"
  | Swap_server _                      -> "swap_server"
  | Root_path _                        -> "root_path"
  | Extension_path _                   -> "extension_path"
  | Ipforwarding _                     -> "ip_forwarding"
  | Nlsr _                             -> "nlsr"
  | Policy_filters _                   -> "policy_filters"
  | Max_datagram _                     -> "max_datagram"
  | Default_ip_ttl _                   -> "default_ip_ttl"
  | Pmtu_ageing_timo _                 -> "pmtu_ageing_timeout"
  | Pmtu_plateau_table _               -> "pmtu_plateau_table"
  | Interface_mtu _                    -> "interface_mtu"
  | All_subnets_local _                -> "all_subnets_local"
  | Broadcast_addr _                   -> "broadcast_addr"
  | Perform_mask_discovery _           -> "perform_mask_discovery"
  | Mask_supplier _                    -> "mask_supplier"
  | Perform_router_disc _              -> "perform_router_disc"
  | Router_sol_addr _                  -> "router_solicitation_addr"
  | Static_routes _                    -> "static_routes"
  | Trailer_encapsulation _            -> "trailer_encapsulation"
  | Arp_cache_timo _                   -> "arp_cache_timeout"
  | Ethernet_encapsulation _           -> "ethernet_encapsulation"
  | Tcp_default_ttl _                  -> "tcp_default_ttl"
  | Tcp_keepalive_interval _           -> "tcp_keepalive_interval"
  | Tcp_keepalive_garbage _            -> "tcp_keepalive_garbage"
  | Nis_domain _                       -> "nis_domain"
  | Nis_servers _                      -> "nis_servers"
  | Ntp_servers _                      -> "ntp_servers"
  | Vendor_specific _                  -> "vendor_specific"
  | Netbios_name_servers _             -> "netbios_name_servers"
  | Netbios_datagram_distrib_servers _ -> "netbios_datagram_distrib_servers"
  | Netbios_node _                     -> "netbios_node"
  | Netbios_scope _                    -> "netbios_scope"
  | Xwindow_font_servers _             -> "xwindow_font_servers"
  | Xwindow_display_managers _         -> "xwindow_display_managers"
  | Request_ip _                       -> "request_ip"
  | Ip_lease_time _                    -> "ip_lease_time"
  | Option_overload _                  -> "option_overload"
  | Dhcp_message_type _                -> "dhcp_message_type"
  | Server_identifier _                -> "server_identifier"
  | Parameter_requests _               -> "parameter_requests"
  | Message _                          -> "message"
  | Max_message _                      -> "max_message"
  | Renewal_t1 _                       -> "renewal_t1"
  | Rebinding_t2 _                     -> "rebinding_t2"
  | Vendor_class_id _                  -> "vendor_class_id"
  | Client_id _                        -> "client_id"
  | Nis_plus_domain _                  -> "nis_plus_domain"
  | Nis_plus_servers _                 -> "nis_plus_servers"
  | Tftp_server_name _                 -> "tftp_server_name"
  | Bootfile_name _                    -> "bootfile_name"
  | Mobile_ip_home_agent _             -> "mobile_ip_home_agent"
  | Smtp_servers _                     -> "smtp_servers"
  | Pop3_servers _                     -> "pop3_servers"
  | Nntp_servers _                     -> "nntp_servers"
  | Www_servers _                      -> "www_servers"
  | Finger_servers _                   -> "finger_servers"
  | Irc_servers _                      -> "irc_servers"
  | Streettalk_servers _               -> "streettalk_servers"
  | Streettalk_da _                    -> "streettalk_da"
  | Unknown                            -> "unknown"

let str_of_options options =
  String.concat " " (List.map str_of_option options)

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
