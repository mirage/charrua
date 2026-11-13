(*
 * Copyright (c) 2015-2017 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 * Copyright (c) 2016-2017 Mindy Preston
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

let ( let* ) = Result.bind

let guard p e = if p then Result.Ok () else Result.Error e

let find_option f t =
  let rec loop = function
    | [] -> None
    | x :: l ->
      match f x with
      | None -> loop l
      | Some _ as r -> r
  in
  loop t

let filter_map f l =
  List.rev @@
  List.fold_left (fun a v -> match f v with Some v' -> v'::a | None -> a) [] l

let string_nul b =
  let len = String.length b in
  let rec loop i =
    if i = len then
      true
    else if (String.get b i) <> (Char.chr 0) then
      false
    else
      loop (succ i)
  in
  loop 0

let cstruct_copy_normalized f buf =
  let b = f buf in
  if string_nul b then "" else b

let string_extend_if_le s m =
  let n = String.length s in
  if n > m then
    invalid_arg ("string is too damn big: " ^ (string_of_int n));
  s ^ String.make (m - n) (Char.chr 0)

(*
type dhcp = {
  op:     uint8_t;
  htype:  uint8_t;
  hlen:   uint8_t;
  hops:   uint8_t;
  xid:    uint32_t;
  secs:   uint16_t;
  flags:  uint16_t;
  ciaddr: uint32_t;
  yiaddr: uint32_t;
  siaddr: uint32_t;
  giaddr: uint32_t;
  chaddr: uint8_t   [@len 16];
  sname:  uint8_t   [@len 64];
  file:   uint8_t   [@len 128];
} [@@big_endian]
*)

module Chk = struct
  let add chk cs =
    let len = String.length cs in
    let rec go chk idx =
      let chk = (chk land 0xffff) + (chk lsr 16) in
      if idx + 1 < len then go (chk + String.get_uint16_be cs idx) (idx + 2)
      else if idx < len then go (chk + String.get_uint8 cs idx lsl 8) (idx + 1)
      else chk in
    go chk 0

  let get chk =
    let chk = (chk land 0xffff) + (chk lsr 16) in
    let chk = (chk land 0xffff) + (chk lsr 16) in
    (lnot chk) land 0xffff
end

let get_dhcp_op cs off = String.get_uint8 cs off
let set_dhcp_op cs off v = Bytes.set_uint8 cs off v

let get_dhcp_htype cs off = String.get_uint8 cs (off + 1)
let set_dhcp_htype cs off v = Bytes.set_uint8 cs (off + 1) v

let get_dhcp_hlen cs off = String.get_uint8 cs (off + 2)
let set_dhcp_hlen cs off v = Bytes.set_uint8 cs (off + 2) v

let get_dhcp_hops cs off = String.get_uint8 cs (off + 3)
let set_dhcp_hops cs off v = Bytes.set_uint8 cs (off + 3) v

let get_dhcp_xid cs off = String.get_int32_be cs (off + 4)
let set_dhcp_xid cs off v = Bytes.set_int32_be cs (off + 4) v

let get_dhcp_secs cs off = String.get_uint16_be cs (off + 8)
let set_dhcp_secs cs off v = Bytes.set_uint16_be cs (off + 8) v

let get_dhcp_flags cs off = String.get_uint16_be cs (off + 10)
let set_dhcp_flags cs off v = Bytes.set_uint16_be cs (off + 10) v

let get_dhcp_ciaddr cs off = String.get_int32_be cs (off + 12)
let set_dhcp_ciaddr cs off v = Bytes.set_int32_be cs (off + 12) v

let get_dhcp_yiaddr cs off = String.get_int32_be cs (off + 16)
let set_dhcp_yiaddr cs off v = Bytes.set_int32_be cs (off + 16) v

let get_dhcp_siaddr cs off = String.get_int32_be cs (off + 20)
let set_dhcp_siaddr cs off v = Bytes.set_int32_be cs (off + 20) v

let get_dhcp_giaddr cs off = String.get_int32_be cs (off + 24)
let set_dhcp_giaddr cs off v = Bytes.set_int32_be cs (off + 24) v

let get_dhcp_chaddr cs off = String.sub cs (off + 28) 16
let copy_dhcp_chaddr cs off = get_dhcp_chaddr cs off
let set_dhcp_chaddr src srcoff cs off = Bytes.blit_string src srcoff cs (off + 28) 16

let get_dhcp_sname cs off = String.sub cs (off + 44) 64
let copy_dhcp_sname cs off = get_dhcp_sname cs off
let set_dhcp_sname src srcoff cs off = Bytes.blit_string src srcoff cs (off + 44) 64

let get_dhcp_file cs off = String.sub cs (off + 108) 128
let copy_dhcp_file cs off = get_dhcp_file cs off
let set_dhcp_file src srcoff cs off = Bytes.blit_string src srcoff cs (off + 108) 128

let sizeof_ethernet = 14
let sizeof_ipv4 = 20
let sizeof_udp = 8
let sizeof_dhcp = 236

type op =
  | BOOTREQUEST (* 1 *)
  | BOOTREPLY   (* 2 *)

let op_to_string = function
  | BOOTREQUEST -> "BOOT REQUEST"
  | BOOTREPLY -> "BOOT REPLY"

let int_to_op = function
  | 1 -> Some BOOTREQUEST
  | 2 -> Some BOOTREPLY
  | _ -> None

let int_to_op_exn v = Option.get (int_to_op v)

let op_to_int = function
  | BOOTREQUEST -> 1
  | BOOTREPLY -> 2

type msgtype =
  | DHCPDISCOVER (* 1 *)
  | DHCPOFFER
  | DHCPREQUEST
  | DHCPDECLINE
  | DHCPACK
  | DHCPNAK
  | DHCPRELEASE
  | DHCPINFORM
  | DHCPFORCERENEW
  | DHCPLEASEQUERY
  | DHCPLEASEUNASSIGNED
  | DHCPLEASEUNKNOWN
  | DHCPLEASEACTIVE
  | DHCPBULKLEASEQUERY
  | DHCPLEASEQUERYDONE

let msgtype_to_string = function
  | DHCPDISCOVER -> "DHCP DISCOVER"
  | DHCPOFFER -> "DHCP OFFER"
  | DHCPREQUEST -> "DHCP REQUEST"
  | DHCPDECLINE -> "DHCP DECLINE"
  | DHCPACK -> "DHCP ACK"
  | DHCPNAK -> "DHCP NAK"
  | DHCPRELEASE -> "DHCP RELEASE"
  | DHCPINFORM -> "DHCP INFORM"
  | DHCPFORCERENEW -> "DHCP FORCE RENEW"
  | DHCPLEASEQUERY -> "DHCP LEASE QUERY"
  | DHCPLEASEUNASSIGNED -> "DHCP LEASE UNASSIGNED"
  | DHCPLEASEUNKNOWN -> "DHCP LEASE UNKNOWN"
  | DHCPLEASEACTIVE -> "DHCP LEASE ACTIVE"
  | DHCPBULKLEASEQUERY -> "DHCP BULK LEASE QUERY"
  | DHCPLEASEQUERYDONE -> "DHCP LEASE QUERY DONE"

let int_to_msgtype = function
  | 1 -> Some DHCPDISCOVER
  | 2 -> Some DHCPOFFER
  | 3 -> Some DHCPREQUEST
  | 4 -> Some DHCPDECLINE
  | 5 -> Some DHCPACK
  | 6 -> Some DHCPNAK
  | 7 -> Some DHCPRELEASE
  | 8 -> Some DHCPINFORM
  | 9 -> Some DHCPFORCERENEW
  | 10 -> Some DHCPLEASEQUERY
  | 11 -> Some DHCPLEASEUNASSIGNED
  | 12 -> Some DHCPLEASEUNKNOWN
  | 13 -> Some DHCPLEASEACTIVE
  | 14 -> Some DHCPBULKLEASEQUERY
  | 15 -> Some DHCPLEASEQUERYDONE
  | _ -> None

let int_to_msgtype_exn v = Option.get (int_to_msgtype v)

let msgtype_to_int = function
  | DHCPDISCOVER -> 1
  | DHCPOFFER -> 2
  | DHCPREQUEST -> 3
  | DHCPDECLINE -> 4
  | DHCPACK -> 5
  | DHCPNAK -> 6
  | DHCPRELEASE -> 7
  | DHCPINFORM -> 8
  | DHCPFORCERENEW -> 9
  | DHCPLEASEQUERY -> 10
  | DHCPLEASEUNASSIGNED -> 11
  | DHCPLEASEUNKNOWN -> 12
  | DHCPLEASEACTIVE -> 13
  | DHCPBULKLEASEQUERY -> 14
  | DHCPLEASEQUERYDONE -> 15

type option_code =
  | PAD [@id 0]
  | SUBNET_MASK [@id 1]
  | TIME_OFFSET [@id 2]
  | ROUTERS [@id 3]
  | DNS_SERVERS [@id 6]
  | LOG_SERVERS [@id 7]
  | LPR_SERVERS [@id 9]
  | HOSTNAME [@id 12]
  | BOOTFILE_SIZE [@id 13]
  | DOMAIN_NAME [@id 15]
  | SWAP_SERVER [@id 16]
  | ROOT_PATH [@id 17]
  | EXTENSION_PATH [@id 18]
  | IPFORWARDING [@id 19]
  | NLSR [@id 20]
  | POLICY_FILTERS [@id 21]
  | MAX_DATAGRAM [@id 22]
  | DEFAULT_IP_TTL [@id 23]
  | INTERFACE_MTU [@id 26]
  | ALL_SUBNETS_LOCAL [@id 27]
  | BROADCAST_ADDR [@id 28]
  | PERFORM_ROUTER_DISC [@id 31]
  | ROUTER_SOL_ADDR [@id 32]
  | STATIC_ROUTES [@id 33]
  | TRAILER_ENCAPSULATION [@id 34]
  | ARP_CACHE_TIMO [@id 35]
  | ETHERNET_ENCAPSULATION [@id 36]
  | TCP_DEFAULT_TTL [@id 37]
  | TCP_KEEPALIVE_INTERVAL [@id 38]
  | NIS_DOMAIN [@id 40]
  | NIS_SERVERS [@id 41]
  | NTP_SERVERS [@id 42]
  | VENDOR_SPECIFIC [@id 43]
  | NETBIOS_NAME_SERVERS [@id 44]
  | NETBIOS_DATAGRAM_DISTRIB_SERVERS [@id 45]
  | NETBIOS_NODE [@id 46]
  | NETBIOS_SCOPE [@id 47]
  | XWINDOW_FONT_SERVERS [@id 48]
  | XWINDOW_DISPLAY_MANAGERS [@id 49]
  | REQUEST_IP [@id 50]
  | IP_LEASE_TIME [@id 51]
  | OPTION_OVERLOAD [@id 52]
  | MESSAGE_TYPE [@id 53]
  | SERVER_IDENTIFIER [@id 54]
  | PARAMETER_REQUESTS [@id 55]
  | MESSAGE [@id 56]
  | MAX_MESSAGE [@id 57]
  | RENEWAL_T1 [@id 58]
  | REBINDING_T2 [@id 59]
  | VENDOR_CLASS_ID [@id 60]
  | CLIENT_ID [@id 61]
  | NIS_PLUS_DOMAIN [@id 64]
  | NIS_PLUS_SERVERS [@id 65]
  | TFTP_SERVER_NAME [@id 66]
  | BOOTFILE_NAME [@id 67]
  | MOBILE_IP_HOME_AGENT [@id 68]
  | SMTP_SERVERS [@id 69]
  | POP3_SERVERS [@id 70]
  | NNTP_SERVERS [@id 71]
  | IRC_SERVERS [@id 74]
  | USER_CLASS [@id 77]
  | RAPID_COMMIT [@id 80]
  | CLIENT_FQDN [@id 81]
  | RELAY_AGENT_INFORMATION [@id 82]
  | CLIENT_SYSTEM [@id 93]
  | CLIENT_NDI [@id 94]
  | UUID_GUID [@id 97]
  | PCODE [@id 100]
  | TCODE [@id 101]
  | IPV6ONLY [@id 108]
  | SUBNET_SELECTION [@id 118]
  | DOMAIN_SEARCH [@id 119]
  | SIP_SERVERS [@id 120]
  | CLASSLESS_STATIC_ROUTE [@id 121]
  | VI_VENDOR_CLASS [@id 124]
  | VI_VENDOR_INFO [@id 125]
  | MISC_150 [@id 150]
  | PRIVATE_CLASSLESS_STATIC_ROUTE [@id 249]
  | WEB_PROXY_AUTO_DISC [@id 252]
  | END [@id 255]
  | OTHER of int

let option_code_to_string = function
  | PAD -> "PAD"
  | SUBNET_MASK -> "Subnet mask"
  | TIME_OFFSET -> "Time offset"
  | ROUTERS -> "Routers"
  | DNS_SERVERS -> "DNS servers"
  | LOG_SERVERS -> "Log servers"
  | LPR_SERVERS -> "LPR servers"
  | HOSTNAME -> "Hostname"
  | BOOTFILE_SIZE -> "Bootfile size"
  | DOMAIN_NAME -> "Domain name"
  | SWAP_SERVER -> "Swap server"
  | ROOT_PATH -> "Root path"
  | EXTENSION_PATH -> "Extension path"
  | IPFORWARDING -> "IP forwarding"
  | NLSR -> "NLSR"
  | POLICY_FILTERS -> "Policy filters"
  | MAX_DATAGRAM -> "Max datagram"
  | DEFAULT_IP_TTL -> "Default IP TTL"
  | INTERFACE_MTU -> "Interface MTU"
  | ALL_SUBNETS_LOCAL -> "All subnets local"
  | BROADCAST_ADDR -> "Broadcast address"
  | PERFORM_ROUTER_DISC -> "Perform router discovery"
  | ROUTER_SOL_ADDR -> "Router solicitation address"
  | STATIC_ROUTES -> "Static routes"
  | TRAILER_ENCAPSULATION -> "Trailer encapsulation"
  | ARP_CACHE_TIMO -> "ARP cache timeout"
  | ETHERNET_ENCAPSULATION -> "Ethernet encapsulation"
  | TCP_DEFAULT_TTL -> "TCP default TTL"
  | TCP_KEEPALIVE_INTERVAL -> "TCP keep-alive interval"
  | NIS_DOMAIN -> "NIS domain"
  | NIS_SERVERS -> "NIS servers"
  | NTP_SERVERS -> "NTP servers"
  | VENDOR_SPECIFIC -> "Vendor specific"
  | NETBIOS_NAME_SERVERS -> "NETBIOS name servers"
  | NETBIOS_DATAGRAM_DISTRIB_SERVERS -> "NETBIOS datagram distribution servers"
  | NETBIOS_NODE -> "NETBIOS node"
  | NETBIOS_SCOPE -> "NETBIOS scope"
  | XWINDOW_FONT_SERVERS -> "X window font servers"
  | XWINDOW_DISPLAY_MANAGERS -> "X window display managers"
  | REQUEST_IP -> "Request IP"
  | IP_LEASE_TIME -> "IP lease time"
  | OPTION_OVERLOAD -> "Option overload"
  | MESSAGE_TYPE -> "Message type"
  | SERVER_IDENTIFIER -> "Server identifier"
  | PARAMETER_REQUESTS -> "Parameters requests"
  | MESSAGE -> "Message"
  | MAX_MESSAGE -> "Max message"
  | RENEWAL_T1 -> "Renewal T1"
  | REBINDING_T2 -> "Rebinding T2"
  | VENDOR_CLASS_ID -> "Vendor class ID"
  | CLIENT_ID -> "Client ID"
  | NIS_PLUS_DOMAIN -> "NIS+ domain"
  | NIS_PLUS_SERVERS -> "NIS+ servers"
  | TFTP_SERVER_NAME -> "TFTP server name"
  | BOOTFILE_NAME -> "Bootfile name"
  | MOBILE_IP_HOME_AGENT -> "Mobile IP home agent"
  | SMTP_SERVERS -> "SMTP servers"
  | POP3_SERVERS -> "POP3 servers"
  | NNTP_SERVERS -> "NNTP servers"
  | IRC_SERVERS -> "IRC servers"
  | USER_CLASS -> "User class"
  | RAPID_COMMIT -> "Rapid commit"
  | CLIENT_FQDN -> "Client FQDN"
  | RELAY_AGENT_INFORMATION -> "Relay agent information"
  | CLIENT_SYSTEM -> "Client system"
  | CLIENT_NDI -> "Client NDI"
  | UUID_GUID -> "UUID GUID"
  | PCODE -> "PCODE"
  | TCODE -> "TCODE"
  | IPV6ONLY -> "IPv6 only"
  | SUBNET_SELECTION -> "Subnet selection"
  | DOMAIN_SEARCH -> "Domain search"
  | SIP_SERVERS -> "SIP servers"
  | CLASSLESS_STATIC_ROUTE -> "Classless static route"
  | VI_VENDOR_CLASS -> "VI vendor class"
  | VI_VENDOR_INFO -> "VI vendor info"
  | MISC_150 -> "Misc 150"
  | PRIVATE_CLASSLESS_STATIC_ROUTE -> "Private classless static route"
  | WEB_PROXY_AUTO_DISC -> "Web proxy auto discovery"
  | END -> "End"
  | OTHER id -> "Other " ^ string_of_int id

let int_to_option_code = function
  | 0 -> Some PAD
  | 1 -> Some SUBNET_MASK
  | 2 -> Some TIME_OFFSET
  | 3 -> Some ROUTERS
  | 6 -> Some DNS_SERVERS
  | 7 -> Some LOG_SERVERS
  | 9 -> Some LPR_SERVERS
  | 12 -> Some HOSTNAME
  | 13 -> Some BOOTFILE_SIZE
  | 15 -> Some DOMAIN_NAME
  | 16 -> Some SWAP_SERVER
  | 17 -> Some ROOT_PATH
  | 18 -> Some EXTENSION_PATH
  | 19 -> Some IPFORWARDING
  | 20 -> Some NLSR
  | 21 -> Some POLICY_FILTERS
  | 22 -> Some MAX_DATAGRAM
  | 23 -> Some DEFAULT_IP_TTL
  | 26 -> Some INTERFACE_MTU
  | 27 -> Some ALL_SUBNETS_LOCAL
  | 28 -> Some BROADCAST_ADDR
  | 31 -> Some PERFORM_ROUTER_DISC
  | 32 -> Some ROUTER_SOL_ADDR
  | 33 -> Some STATIC_ROUTES
  | 34 -> Some TRAILER_ENCAPSULATION
  | 35 -> Some ARP_CACHE_TIMO
  | 36 -> Some ETHERNET_ENCAPSULATION
  | 37 -> Some TCP_DEFAULT_TTL
  | 38 -> Some TCP_KEEPALIVE_INTERVAL
  | 40 -> Some NIS_DOMAIN
  | 41 -> Some NIS_SERVERS
  | 42 -> Some NTP_SERVERS
  | 43 -> Some VENDOR_SPECIFIC
  | 44 -> Some NETBIOS_NAME_SERVERS
  | 45 -> Some NETBIOS_DATAGRAM_DISTRIB_SERVERS
  | 46 -> Some NETBIOS_NODE
  | 47 -> Some NETBIOS_SCOPE
  | 48 -> Some XWINDOW_FONT_SERVERS
  | 49 -> Some XWINDOW_DISPLAY_MANAGERS
  | 50 -> Some REQUEST_IP
  | 51 -> Some IP_LEASE_TIME
  | 52 -> Some OPTION_OVERLOAD
  | 53 -> Some MESSAGE_TYPE
  | 54 -> Some SERVER_IDENTIFIER
  | 55 -> Some PARAMETER_REQUESTS
  | 56 -> Some MESSAGE
  | 57 -> Some MAX_MESSAGE
  | 58 -> Some RENEWAL_T1
  | 59 -> Some REBINDING_T2
  | 60 -> Some VENDOR_CLASS_ID
  | 61 -> Some CLIENT_ID
  | 64 -> Some NIS_PLUS_DOMAIN
  | 65 -> Some NIS_PLUS_SERVERS
  | 66 -> Some TFTP_SERVER_NAME
  | 67 -> Some BOOTFILE_NAME
  | 68 -> Some MOBILE_IP_HOME_AGENT
  | 69 -> Some SMTP_SERVERS
  | 70 -> Some POP3_SERVERS
  | 71 -> Some NNTP_SERVERS
  | 74 -> Some IRC_SERVERS
  | 77 -> Some USER_CLASS
  | 80 -> Some RAPID_COMMIT
  | 81 -> Some CLIENT_FQDN
  | 82 -> Some RELAY_AGENT_INFORMATION
  | 93 -> Some CLIENT_SYSTEM
  | 94 -> Some CLIENT_NDI
  | 97 -> Some UUID_GUID
  | 100 -> Some PCODE
  | 101 -> Some TCODE
  | 108 -> Some IPV6ONLY
  | 118 -> Some SUBNET_SELECTION
  | 119 -> Some DOMAIN_SEARCH
  | 120 -> Some SIP_SERVERS
  | 121 -> Some CLASSLESS_STATIC_ROUTE
  | 124 -> Some VI_VENDOR_CLASS
  | 125 -> Some VI_VENDOR_INFO
  | 150 -> Some MISC_150
  | 249 -> Some PRIVATE_CLASSLESS_STATIC_ROUTE
  | 252 -> Some WEB_PROXY_AUTO_DISC
  | 255 -> Some END
  | x -> Some (OTHER x)

let int_to_option_code_exn v = Option.get (int_to_option_code v)

let option_code_to_int = function
  | PAD -> 0
  | SUBNET_MASK -> 1
  | TIME_OFFSET -> 2
  | ROUTERS -> 3
  | DNS_SERVERS -> 6
  | LOG_SERVERS -> 7
  | LPR_SERVERS -> 9
  | HOSTNAME -> 12
  | BOOTFILE_SIZE -> 13
  | DOMAIN_NAME -> 15
  | SWAP_SERVER -> 16
  | ROOT_PATH -> 17
  | EXTENSION_PATH -> 18
  | IPFORWARDING -> 19
  | NLSR -> 20
  | POLICY_FILTERS -> 21
  | MAX_DATAGRAM -> 22
  | DEFAULT_IP_TTL -> 23
  | INTERFACE_MTU -> 26
  | ALL_SUBNETS_LOCAL -> 27
  | BROADCAST_ADDR -> 28
  | PERFORM_ROUTER_DISC -> 31
  | ROUTER_SOL_ADDR -> 32
  | STATIC_ROUTES -> 33
  | TRAILER_ENCAPSULATION -> 34
  | ARP_CACHE_TIMO -> 35
  | ETHERNET_ENCAPSULATION -> 36
  | TCP_DEFAULT_TTL -> 37
  | TCP_KEEPALIVE_INTERVAL -> 38
  | NIS_DOMAIN -> 40
  | NIS_SERVERS -> 41
  | NTP_SERVERS -> 42
  | VENDOR_SPECIFIC -> 43
  | NETBIOS_NAME_SERVERS -> 44
  | NETBIOS_DATAGRAM_DISTRIB_SERVERS -> 45
  | NETBIOS_NODE -> 46
  | NETBIOS_SCOPE -> 47
  | XWINDOW_FONT_SERVERS -> 48
  | XWINDOW_DISPLAY_MANAGERS -> 49
  | REQUEST_IP -> 50
  | IP_LEASE_TIME -> 51
  | OPTION_OVERLOAD -> 52
  | MESSAGE_TYPE -> 53
  | SERVER_IDENTIFIER -> 54
  | PARAMETER_REQUESTS -> 55
  | MESSAGE -> 56
  | MAX_MESSAGE -> 57
  | RENEWAL_T1 -> 58
  | REBINDING_T2 -> 59
  | VENDOR_CLASS_ID -> 60
  | CLIENT_ID -> 61
  | NIS_PLUS_DOMAIN -> 64
  | NIS_PLUS_SERVERS -> 65
  | TFTP_SERVER_NAME -> 66
  | BOOTFILE_NAME -> 67
  | MOBILE_IP_HOME_AGENT -> 68
  | SMTP_SERVERS -> 69
  | POP3_SERVERS -> 70
  | NNTP_SERVERS -> 71
  | IRC_SERVERS -> 74
  | USER_CLASS -> 77
  | RAPID_COMMIT -> 80
  | CLIENT_FQDN -> 81
  | RELAY_AGENT_INFORMATION -> 82
  | CLIENT_SYSTEM -> 93
  | CLIENT_NDI -> 94
  | UUID_GUID -> 97
  | PCODE -> 100
  | TCODE -> 101
  | IPV6ONLY -> 108
  | SUBNET_SELECTION -> 118
  | DOMAIN_SEARCH -> 119
  | SIP_SERVERS -> 120
  | CLASSLESS_STATIC_ROUTE -> 121
  | VI_VENDOR_CLASS -> 124
  | VI_VENDOR_INFO -> 125
  | MISC_150 -> 150
  | PRIVATE_CLASSLESS_STATIC_ROUTE -> 249
  | WEB_PROXY_AUTO_DISC -> 252
  | END -> 255
  | OTHER x -> x

type htype =
  | Ethernet_10mb
  | Other

let htype_to_string = function
  | Ethernet_10mb -> "Ethernet 10MB"
  | Other -> "Other"

type flags =
  | Broadcast
  | Unicast

let flags_to_string = function
  | Broadcast -> "Broadcast"
  | Unicast -> "Unicast"

type client_id =
  | Hwaddr of Macaddr.t
  | Id of int * string

let client_id_to_string = function
  | Hwaddr mac -> "MAC " ^ Macaddr.to_string mac
  | Id (id, txt) -> "ID " ^ string_of_int id ^ " " ^ Ohex.encode txt

let string_to_client_id = function
  | s when String.starts_with ~prefix:"MAC " s ->
    Result.to_option
      (Result.map (fun mac -> Hwaddr mac)
         (Macaddr.of_string (String.sub s 4 (String.length s - 4))))
  | s when String.starts_with ~prefix:"ID " s ->
    (match String.split_on_char ' ' s with
     | [ _id ; id ; txt ]->
       (match int_of_string_opt id with
        | None -> None
        | Some id -> Some (Id (id, Ohex.decode txt)))
     | _ -> None)
  | _ -> None

(* from RFC 4702 *)
type client_fqdn =
  [ `Server_A (* C2S server should register A in DNS *)
  | `Overriden (* S2C DNS entry was overriden *)
  | `No_update (* C2S should not do any DNS updates *)
  | `Wire_encoding (* both, if not set some deprecated ASCII encoding *)
  ] list *
  (* rcode_1 and rcode_2, both ignored *)
  [ `raw ] Domain_name.t

let client_fqdn_to_string (flags, fqdn) =
  let flag_to_string = function
    | `Server_A -> "S"
    | `Overriden -> "O"
    | `No_update -> "N"
    | `Wire_encoding -> "E"
  in
  String.concat "" (List.map flag_to_string flags) ^ ", " ^
  Domain_name.to_string fqdn

let string_to_client_fqdn data =
  let char_to_flag = function
    | 'S' -> Some `Server_A
    | 'O' -> Some `Overriden
    | 'N' -> Some `No_update
    | 'E' -> Some `Wire_encoding
    | _ -> None
  in
  let flags, fqdn =
    match String.split_on_char ' ' data with
    | [] -> "", ""
    | f :: rest -> f, String.concat " " rest
  in
  String.fold_left (fun acc c -> match char_to_flag c with
      | Some f -> f :: acc
      | None -> acc)
    [] flags,
  match Domain_name.of_string fqdn with Ok s -> s | Error _ -> Domain_name.root

type dhcp_option =
  | Pad                                     (* code 0 *)
  | Subnet_mask of Ipaddr.V4.t         (* code 1 *)
  | Time_offset of int32                    (* code 2 *)
  | Routers of Ipaddr.V4.t list        (* code 3 *)
  | Dns_servers of Ipaddr.V4.t list         (* code 6 *)
  | Log_servers of Ipaddr.V4.t list         (* code 7 *)
  | Lpr_servers of Ipaddr.V4.t list         (* code 9 *)
  | Hostname of string                      (* code 12 *)
  | Bootfile_size of int                    (* code 13 *)
  | Domain_name of string                   (* code 15 *)
  | Swap_server of Ipaddr.V4.t              (* code 16 *)
  | Root_path of string                     (* code 17 *)
  | Extension_path of string                (* code 18 *)
  | Ipforwarding of bool                    (* code 19 *)
  | Nlsr of bool                            (* code 20 *)
  | Policy_filters of Ipaddr.V4.Prefix.t list (* code 21 *)
  | Max_datagram of int                     (* code 22 *)
  | Default_ip_ttl of int                   (* code 23 *)
  | Interface_mtu of int                    (* code 26 *)
  | All_subnets_local of bool               (* code 27 *)
  | Broadcast_addr of Ipaddr.V4.t           (* code 28 *)
  | Perform_router_disc of bool             (* code 31 *)
  | Router_sol_addr of Ipaddr.V4.t          (* code 32 *)
  | Static_routes of (Ipaddr.V4.t * Ipaddr.V4.t) list (* code 33 *)
  | Trailer_encapsulation of bool           (* code 34 *)
  | Arp_cache_timo of int32                 (* code 35 *)
  | Ethernet_encapsulation of bool          (* code 36 *)
  | Tcp_default_ttl of int                  (* code 37 *)
  | Tcp_keepalive_interval of int32         (* code 38 *)
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
  | Ip_lease_time of int32                  (* code 51 *)
  | Option_overload of int                  (* code 52 *)
  | Message_type of msgtype                 (* code 53 *)
  | Server_identifier of Ipaddr.V4.t        (* code 54 *)
  | Parameter_requests of option_code list  (* code 55 *)
  | Message of string                       (* code 56 *)
  | Max_message of int                      (* code 57 *)
  | Renewal_t1 of int32                     (* code 58 *)
  | Rebinding_t2 of int32                   (* code 59 *)
  | Vendor_class_id of string               (* code 60 *)
  | Client_id of client_id                  (* code 61 *)
  | Nis_plus_domain of string               (* code 64 *)
  | Nis_plus_servers of Ipaddr.V4.t list    (* code 65 *)
  | Tftp_server_name of string              (* code 66 *)
  | Bootfile_name of string                 (* code 67 *)
  | Mobile_ip_home_agent of Ipaddr.V4.t list(* code 68 *)
  | Smtp_servers of Ipaddr.V4.t list        (* code 69 *)
  | Pop3_servers of Ipaddr.V4.t list        (* code 70 *)
  | Nntp_servers of Ipaddr.V4.t list        (* code 71 *)
  | Irc_servers of Ipaddr.V4.t list         (* code 74 *)
  | User_class of string                    (* code 77 *)
  | Rapid_commit                            (* code 80 *)
  | Client_fqdn of client_fqdn              (* code 81 *)
  | Relay_agent_information of string       (* code 82 *)
  | Client_system of string                 (* code 93 *)
  | Client_ndi of string                    (* code 94 *)
  | Uuid_guid of string                     (* code 97 *)
  | Pcode of string                         (* code 100 *)
  | Tcode of string                         (* code 101 *)
  | IPv6_only of int32                      (* code 108 *)
  | Subnet_selection of Ipaddr.V4.t    (* code 118 *)
  | Domain_search of string                 (* code 119 *)
  | Sip_servers of string                   (* code 120 *)
  | Classless_static_route of string        (* code 121 *) (* XXX current, use better type *)
  | Vi_vendor_class of                      (* code 124 *)
      (int32 * string list) list
  | Vi_vendor_info of                       (* code 125 *)
      (int32 * (int * string) list) list
  | Misc_150 of string                      (* code 150 *)
  | Private_classless_static_route of string(* code 249 *) (* XXX current, use better type *)
  | Web_proxy_auto_disc of string           (* code 252 *)
  | End                                     (* code 255 *)
  | Other of int * string              (* code * string *)

let dhcp_option_to_string = function
  | Pad -> "Pad"
  | Subnet_mask ip -> "Subnet mask " ^ Ipaddr.V4.to_string ip
  | Time_offset off -> "Time offset " ^ Int32.to_string off
  | Routers ips -> "Routers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Dns_servers ips -> "DNS servers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Log_servers ips -> "Log servers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Lpr_servers ips -> "LPR servers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Hostname s -> "Hostname " ^ s
  | Bootfile_size s -> "Bootfile size " ^ string_of_int s
  | Domain_name s -> "Domain name " ^ s
  | Swap_server ip -> "Swap server " ^ Ipaddr.V4.to_string ip
  | Root_path s -> "Root path " ^ s
  | Extension_path s -> "Extension path " ^ s
  | Ipforwarding b -> "IP forwarding " ^ string_of_bool b
  | Nlsr b -> "NLSR " ^ string_of_bool b
  | Policy_filters f -> "Policy filters " ^ String.concat ", " (List.map Ipaddr.V4.Prefix.to_string f)
  | Max_datagram s -> "Max datagram " ^ string_of_int s
  | Default_ip_ttl s -> "Default IP TTL " ^ string_of_int s
  | Interface_mtu s -> "Interface MTU " ^ string_of_int s
  | All_subnets_local b -> "All subnets local " ^ string_of_bool b
  | Broadcast_addr ip -> "Broadcast address " ^ Ipaddr.V4.to_string ip
  | Perform_router_disc b -> "Perform router discovery " ^ string_of_bool b
  | Router_sol_addr ip -> "Router solicitation address " ^ Ipaddr.V4.to_string ip
  | Static_routes routes -> "Static routes " ^ String.concat ", " (List.map (fun (a, b) -> Ipaddr.V4.to_string a ^ " -> " ^ Ipaddr.V4.to_string b) routes)
  | Trailer_encapsulation b -> "Trailer encapsulation " ^ string_of_bool b
  | Arp_cache_timo t -> "ARP cache timeout " ^ Int32.to_string t
  | Ethernet_encapsulation b -> "Ethernet encapsulation " ^ string_of_bool b
  | Tcp_default_ttl t -> "TCP default TTL " ^ string_of_int t
  | Tcp_keepalive_interval t -> "TCP keep-alive interval " ^ Int32.to_string t
  | Nis_domain s -> "NIS domain " ^ s
  | Nis_servers ips -> "NIS servers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Ntp_servers ips -> "NTP servers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Vendor_specific s -> "Vendor specific " ^ s
  | Netbios_name_servers ips -> "NETBIOS name servers "  ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Netbios_datagram_distrib_servers ips -> "NETBIOS datagram distribution servers "  ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Netbios_node i -> "NETBIOS node " ^ string_of_int i
  | Netbios_scope s -> "NETBIOS scope " ^ s
  | Xwindow_font_servers ips -> "XWindow font servers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Xwindow_display_managers ips -> "Xwindow display managers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Request_ip ip -> "Request IP " ^ Ipaddr.V4.to_string ip
  | Ip_lease_time i -> "IP lease time " ^ Int32.to_string i
  | Option_overload i -> "Option overload " ^ string_of_int i
  | Message_type t -> "Message type " ^ msgtype_to_string t
  | Server_identifier ip -> "Server identifier " ^ Ipaddr.V4.to_string ip
  | Parameter_requests ops -> "Parameter request " ^ String.concat ", " (List.map option_code_to_string ops)
  | Message s -> "Message " ^ s
  | Max_message i -> "Max message " ^ string_of_int i
  | Renewal_t1 t -> "Renewal T1 " ^ Int32.to_string t
  | Rebinding_t2 t -> "Rebinding T2 " ^ Int32.to_string t
  | Vendor_class_id s -> "Vendor class ID " ^ s
  | Client_id c -> "Client ID " ^ client_id_to_string c
  | Nis_plus_domain s -> "NIS+ domain " ^ s
  | Nis_plus_servers ips -> "NIS+ servers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Tftp_server_name s -> "TFTP server name " ^ s
  | Bootfile_name s -> "Bootfile name " ^ s
  | Mobile_ip_home_agent ips -> "Mobile IP home agent " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Smtp_servers ips -> "SMTP servers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Pop3_servers ips -> "POP3 servers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Nntp_servers ips -> "NNTP servers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | Irc_servers ips -> "IRC servers " ^ String.concat ", " (List.map Ipaddr.V4.to_string ips)
  | User_class s -> "User class " ^ s
  | Rapid_commit -> "Rapid commit"
  | Client_fqdn s -> "Client FQDN " ^ client_fqdn_to_string s
  | Relay_agent_information s -> "Relay agent information " ^ s
  | Client_system s -> "Client system " ^ s
  | Client_ndi s -> "Client NDI " ^ s
  | Uuid_guid s -> "UUID GUID " ^ s
  | Pcode s -> "PCODE " ^ s
  | Tcode s -> "TCODE " ^ s
  | IPv6_only i -> "IPv6 only " ^ Int32.to_string i
  | Subnet_selection ip -> "Subnet selection " ^ Ipaddr.V4.to_string ip
  | Domain_search s -> "Domain search " ^ s
  | Sip_servers s -> "SIP servers " ^ s
  | Classless_static_route s -> "Classless static route " ^ s
  | Vi_vendor_class _s -> "VI vendor class" (*^ s (* FIXME *)*)
  | Vi_vendor_info _s -> "VI vendor info"
  | Misc_150 s -> "Misc 150 " ^ s
  | Private_classless_static_route s -> "Private classless static route " ^ s
  | Web_proxy_auto_disc s -> "Web proxy auto discovery " ^ s
  | End -> "End"
  | Other (id, s) -> "Other " ^ string_of_int id ^ ": " ^ s

type pkt = {
  srcmac  : Macaddr.t;
  dstmac  : Macaddr.t;
  srcip   : Ipaddr.V4.t;
  dstip   : Ipaddr.V4.t;
  srcport : int;
  dstport : int;
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
  chaddr  : Macaddr.t;
  sname   : string;
  file    : string;
  options : dhcp_option list;
}

let pp_pkt ppf pkt =
  Fmt.pf ppf "src MAC %a dst MAC %a@.src IP %a dst IP %a@.src port %u dst port %u@.operation %s@.htype %s hlen %u hops %u@.XID %lu secs %u flags %s@.ciaddr %a yiaddr %a@.siaddr %a giaddr %a chaddr %a@.sname %s file %s@.options %a"
    Macaddr.pp pkt.srcmac Macaddr.pp pkt.dstmac Ipaddr.V4.pp pkt.srcip Ipaddr.V4.pp pkt.dstip
    pkt.srcport pkt.dstport (op_to_string pkt.op) (htype_to_string pkt.htype) pkt.hlen pkt.hops pkt.xid pkt.secs
    (flags_to_string pkt.flags) Ipaddr.V4.pp pkt.ciaddr Ipaddr.V4.pp pkt.yiaddr Ipaddr.V4.pp pkt.siaddr Ipaddr.V4.pp pkt.giaddr Macaddr.pp pkt.chaddr pkt.sname pkt.file Fmt.(list ~sep:(any ", ") string) (List.map dhcp_option_to_string pkt.options)


let client_port = 68
let server_port = 67

let options_of_buf buf off buf_len =
  let rec collect buf off options =
    let code = String.get_uint8 buf off in
    let padding () = collect buf (off + 1) options in
    (* Make sure we never shift into an unexisting body *)
    match int_to_option_code_exn code with
    | PAD -> padding ()
    | END -> off, options
    | _ -> (* Has len:body, generate the get functions *)
      let len = String.get_uint8 buf (off + 1) in
      let bad_len () = Printf.sprintf "Malformed len %d in option %d" len code in
      (* discard discards the option from the resulting list *)
      let discard () = collect buf (off + len + 2) options in
      (* take includes the option in the resulting list *)
      let take op = collect buf (off + len + 2) (op :: options) in
      let get_8 () = if len <> 1 then invalid_arg (bad_len ()) else
          String.get_uint8 buf (off + 2) in
      let get_8_list ?(min_len=1) () =
        let rec loop offset octets =
          if offset = len then octets else
            let octet = String.get_uint8 buf (off + 2 + offset) in
            loop (succ offset) (octet :: octets)
        in
        if len < min_len then invalid_arg (bad_len ()) else
          List.rev (loop 0 [])
      in
      let get_bool () = match (get_8 ()) with
        | 1 -> true
        | 0 -> false
        | v -> invalid_arg ("invalid value for bool: " ^ string_of_int v)
      in
      let get_16 () = if len <> 2 then invalid_arg (bad_len ()) else
          String.get_uint16_be buf (off + 2) in
      let get_32 () = if len <> 4 then invalid_arg (bad_len ()) else
          String.get_int32_be buf (off + 2) in
      let get_32_list ?(min_len=4) () =
        let rec loop offset longs =
          if offset = len then longs else
            let long = String.get_int32_be buf (off + 2 + offset) in
            loop (offset + 4) (long :: longs)
        in
        if ((len mod 4) <> 0) || len < min_len then invalid_arg (bad_len ()) else
          List.rev (loop 0 [])
      in
      (* Fetch ipv4s from options *)
      let get_ip () = if len <> 4 then invalid_arg (bad_len ()) else
          Ipaddr.V4.of_int32 (get_32 ()) in
      let get_ip_list ?(min_len=4) () =
        List.map Ipaddr.V4.of_int32 (get_32_list ~min_len:min_len ())
      in
      let get_ip_tuple_list _ =
        let rec loop ips tuples = match ips with
          | ip1 :: ip2 :: tl -> loop tl ((ip1, ip2) :: tuples)
          | _ip :: [] -> invalid_arg (bad_len ())
          | [] -> List.rev tuples
        in
        loop (get_ip_list ~min_len:8 ()) []
      in
      (* Get a list of ip pairs *)
      let get_prefix_list ?(min_len=8) () =
        if ((len mod 8) <> 0) || len < min_len then
          invalid_arg (bad_len ())
        else
          List.map (function
              | address, netmask -> try
                  Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address
                with
                  Ipaddr.Parse_error (a, b) -> invalid_arg (a ^ ": " ^ b))
            (get_ip_tuple_list ())
      in
      let get_string () =  if len < 1 then invalid_arg (bad_len ()) else
          String.sub buf (off + 2) len
      in
      let get_client_id () =  if len < 2 then invalid_arg (bad_len ()) else
          let htype = String.get_uint8 buf (off + 2) in
          let s = String.sub buf (off + 3) (len - 1) in
          if htype = 1 && len = 7 then
            Hwaddr (Macaddr.of_octets_exn s)
          else
            Id (htype, s)
      in
      let get_client_fqdn () = if len < 4 then invalid_arg (bad_len ()) else
          let rec parse_domain_name acc idx data =
            let sl = String.length data in
            if sl - idx = 0 then
              Domain_name.of_strings (List.rev acc)
            else
              let l = String.get_uint8 data idx in
              if l <= sl - idx - 1 then
                let lbl = String.sub data (idx + 1) l in
                parse_domain_name (lbl :: acc) (idx + l + 1) data
              else
                Error (`Msg "invalid length")
          in
          let flags =
            let d = String.get_uint8 buf (off + 2) in
            (if d land 0x1 > 0 then [ `Server_A ] else []) @
            (if d land 0x2 > 0 then [ `Overriden ] else []) @
            (if d land 0x4 > 0 then [ `Wire_encoding ] else []) @
            (if d land 0x8 > 0 then [ `No_update ] else [])
          in
          let fqdn =
            let d = String.sub buf (off + 2 + 3) (len - 3) in
            match
              if List.mem `Wire_encoding flags then
                parse_domain_name [] 0 d
              else
                Domain_name.of_string d
            with
              | Ok n -> n
              | Error `Msg s -> invalid_arg s
          in
          flags, fqdn
      in
      let get_vi_vendor_thing () =
        if len < 5 then invalid_arg (bad_len ());
        let[@tail_mod_cons] rec loop offset =
          if offset = len then []
          else if len < offset + 5 then
            invalid_arg (bad_len ())
          else
            let pen = String.get_int32_be buf (off + 2 + offset) in
            let data_len = String.get_uint8 buf (off + 2 + offset + 4) in
            if len < offset + 5 + data_len then
              invalid_arg (bad_len ())
            else
              let data = String.sub buf (off + 2 + offset + 5) data_len in
              (pen, data) :: (loop[@tailcall]) (offset + 5 + data_len)
        in
        loop 0
      in
      let get_vi_vendor_info () =
        List.map (fun (pen, data) ->
            let[@tail_mod_cons] rec go offset =
              let bad_len len =
                Fmt.kstr invalid_arg
                  "Malformed len %d in vendor-identifying vendor information sub-option"
                  len
              in
              if String.length data - offset < 2 then bad_len (String.length data - offset);
              let code = String.get_uint8 data offset in
              let len = String.get_uint8 data (offset + 1) in
              if String.length data - offset < 2 + len then bad_len (String.length data - offset - 2);
              let sub_option = (code, String.sub data (offset + 2) len) in
              let offset = offset + 2 + len in
              if offset = String.length data then
                [sub_option]
              else
                sub_option :: (go[@tailcall]) offset
            in
            (pen, go 0))
          (get_vi_vendor_thing ())
      in
      let get_vi_vendor_class () =
        List.map (fun (pen, datas) ->
            let[@tail_mod_cons] rec go offset =
              let bad_len len =
                Fmt.kstr invalid_arg
                  "Malformed len %d in vendor-identifying vendor class data"
                  len
              in
              if String.length datas - offset < 1 then bad_len (String.length datas - offset);
              let len = String.get_uint8 datas offset in
              if String.length datas - offset < 1 + len then bad_len len;
              let data = String.sub datas (offset + 1) len in
              let offset = offset + 1 + len in
              if offset = String.length datas then
                [data]
              else
                data :: (go[@tailcall]) offset
            in
            (pen, go 0))
          (get_vi_vendor_thing ())
      in
      match code with
      | 0 ->   padding ()
      | 1 ->   take (Subnet_mask (get_ip ()))
      | 2 ->   take (Time_offset (get_32 ()))
      | 3 ->   take (Routers (get_ip_list ()))
      | 6 ->   take (Dns_servers (get_ip_list ()))
      | 7 ->   take (Log_servers (get_ip_list ()))
      | 9 ->   take (Lpr_servers (get_ip_list ()))
      | 12 ->  take (Hostname (get_string ()))
      | 13 ->  take (Bootfile_size (get_16 ()))
      | 15 ->  take (Domain_name (get_string ()))
      | 16 ->  take (Swap_server (get_ip ()))
      | 17 ->  take (Root_path (get_string ()))
      | 18 ->  take (Extension_path (get_string ()))
      | 19 ->  take (Ipforwarding (get_bool ()))
      | 20 ->  take (Nlsr (get_bool ()))
      | 21 ->  take (Policy_filters (get_prefix_list ()))
      | 22 ->  take (Max_datagram (get_16 ()))
      | 23 ->  take (Default_ip_ttl (get_8 ()))
      | 26 ->  take (Interface_mtu (get_16 ()))
      | 27 ->  take (All_subnets_local (get_bool ()))
      | 28 ->  take (Broadcast_addr (get_ip ()))
      | 31 ->  take (Perform_router_disc (get_bool ()))
      | 32 ->  take (Router_sol_addr (get_ip ()))
      | 33 ->  take (Static_routes (get_ip_tuple_list ()))
      | 34 ->  take (Trailer_encapsulation (get_bool ()))
      | 35 ->  take (Arp_cache_timo (get_32 ()))
      | 36 ->  take (Ethernet_encapsulation (get_bool ()))
      | 37 ->  take (Tcp_default_ttl (get_8 ()))
      | 38 ->  take (Tcp_keepalive_interval (get_32 ()))
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
      | 53 ->  take (Message_type (int_to_msgtype_exn (get_8 ())))
      | 54 ->  take (Server_identifier (get_ip ()))
      | 55 ->  take (Parameter_requests
                       (get_8_list () |>
                        List.map int_to_option_code_exn))
      | 56 ->  take (Message (get_string ()))
      | 57 ->  take (Max_message (get_16 ()))
      | 58 ->  take (Renewal_t1 (get_32 ()))
      | 59 ->  take (Rebinding_t2 (get_32 ()))
      | 60 ->  take (Vendor_class_id (get_string ()))
      | 61 ->  take (Client_id (get_client_id ()))
      | 64 ->  take (Nis_plus_domain (get_string ()))
      | 65 ->  take (Nis_plus_servers (get_ip_list ()))
      | 66 ->  take (Tftp_server_name (get_string ()))
      | 67 ->  take (Bootfile_name (get_string ()))
      | 68 ->  take (Mobile_ip_home_agent (get_ip_list ~min_len:0 ()))
      | 69 ->  take (Smtp_servers (get_ip_list ()))
      | 70 ->  take (Pop3_servers (get_ip_list ()))
      | 71 ->  take (Nntp_servers (get_ip_list ()))
      | 74 ->  take (Irc_servers (get_ip_list ()))
      | 77 ->  take (User_class (get_string ()))
      | 80 ->  take Rapid_commit
      | 81 ->  take (Client_fqdn (get_client_fqdn ()))
      | 82 ->  take (Relay_agent_information (get_string ()))
      | 93 ->  take (Client_system (get_string ()))
      | 94 ->  take (Client_ndi (get_string ()))
      | 97 ->  take (Uuid_guid (get_string ()))
      | 100 -> take (Pcode (get_string ()))
      | 101 -> take (Tcode (get_string ()))
      | 108 -> take (IPv6_only (get_32 ()))
      | 118 -> take (Subnet_selection (get_ip ()))
      | 119 -> take (Domain_search (get_string ()))
      | 120 -> take (Sip_servers (get_string ()))
      | 121 -> take (Classless_static_route (get_string ()))
      | 124 -> take (Vi_vendor_class (get_vi_vendor_class ()))
      | 125 -> take (Vi_vendor_info (get_vi_vendor_info ()))
      | 150 -> take (Misc_150 (get_string ()))
      | 249 -> take (Private_classless_static_route (get_string ()))
      | 252 -> take (Web_proxy_auto_disc (get_string ()))
      | _code -> discard ()
  in
  (* Extends options if it finds an Option_overload *)
  let extend buf (off, options) =
    let rec search = function
      | [] -> None
      | opt :: tl -> match opt with
        | Option_overload v -> Some v
        | _ -> search tl
    in
    match search options with
    | None -> options           (* Nothing to do, identity function *)
    | Some v -> match v with
      | 1 -> snd (collect (get_dhcp_file buf off) 0 options)    (* It's in file *)
      | 2 -> snd (collect (get_dhcp_sname buf off) 0 options)   (* It's in sname *)
      | 3 ->
        let _off, options =
          collect (get_dhcp_file buf off) 0 options (* OMG both *)
        in
        let _off', options =
          collect (get_dhcp_sname buf off) 0 options
        in
        options
      | _ -> invalid_arg ("Invalid overload code: " ^ string_of_int v)
  in
  (* Handle a pkt with no options *)
  if buf_len = 0 then
    []
  else
    (* Look for magic cookie *)
    let cookie = String.get_int32_be buf off in
    if cookie <> 0x63825363l then
      invalid_arg "Invalid cookie";
    (* Jump over cookie and start options, also extend them if necessary *)
    collect buf (off + 4) [] |>
    extend buf |>
    List.rev

let buf_of_options sbuf options =
  let put_code code buf off = Bytes.set_uint8 buf off code; off + 1 in
  let put_len len buf off = if len > 255 then
      invalid_arg ("option len is too big: " ^ (string_of_int len));
    Bytes.set_uint8 buf off len; off + 1
  in
  let put_8 v buf off = Bytes.set_uint8 buf off v; off + 1 in
  let put_16 v buf off = Bytes.set_uint16_be buf off v; off + 2 in
  let put_32 v buf off = Bytes.set_int32_be buf off v; off + 4 in
  let put_ip ip buf off = put_32 (Ipaddr.V4.to_int32 ip) buf off in
  let put_prefix prefix buf off =
    put_ip (Ipaddr.V4.Prefix.network prefix) buf off |>
    put_ip (Ipaddr.V4.Prefix.netmask prefix) buf
  in
  let put_ip_tuple tuple buf off = match tuple with
    a, b -> put_ip a buf off |> put_ip b buf
  in
  let put_coded_8 code v buf off = put_code code buf off |> put_len 1 buf |> put_8 v buf in
  let put_coded_16 code v buf off = put_code code buf off |> put_len 2 buf |> put_16 v buf in
  let put_coded_32 code v buf off = put_code code buf off |> put_len 4 buf |> put_32 v buf in
  let put_coded_ip code ip buf off = put_code code buf off |> put_len 4 buf |> put_ip ip buf in
  (* let put_coded_prefix code prefix buf = *)
  (*   put_code code buf |> put_len 8 |> put_prefix prefix in *)
  let put_coded_bool code v buf off =
    put_coded_8 code (match v with true -> 1 | false -> 0) buf off in
  let put_coded_bytes code v buf off =
    let len = (String.length v) in
    let off = put_code code buf off |> put_len len buf in
    Bytes.blit_string v 0 buf off len;
    off + len
  in
  let put_client_id code v buf off =
    let htype, s = match v with
      | Hwaddr mac -> (1, Macaddr.to_octets mac)
      | Id (htype, id) -> (htype, id)
    in
    let len = String.length s in
    let off = put_code code buf off |> put_len (succ len) buf |> put_8 htype buf in
    Bytes.blit_string s 0 buf off len;
    off + len
  in
  let put_client_fqdn code (flags, dn) buf off =
    let f =
      (if List.mem `Server_A flags then 0x1 else 0) +
      (if List.mem `Overriden flags then 0x2 else 0) +
      (if List.mem `Wire_encoding flags then 0x4 else 0) +
      (if List.mem `No_update flags then 0x8 else 0)
    in
    let encode_domain_name dn =
      String.concat ""
        (List.map (fun s ->
             let l = String.length s in
             let f = String.make 1 (char_of_int l) in
             f ^ s)
           (Domain_name.to_strings ~trailing:true dn))
    in
    let dn =
      if List.mem `Wire_encoding flags then
        encode_domain_name dn
      else
        Domain_name.to_string dn
    in
    let len = String.length dn in
    (* the last two "put_8 0" are the RCODE, should be 0 for client, and 0xFF
       for server - but should also be ignored by both sides *)
    let off =
      put_code code buf off |> put_len (len + 3) buf |> put_8 f buf |> put_8 0 buf |> put_8 0 buf
    in
    Bytes.blit_string dn 0 buf off len;
    off + len
  in
  let make_listf ?(min_len=1) f len code l (buf : bytes) (off : int) =
    if (List.length l) < min_len then invalid_arg "Invalid option" else
    let off = put_code code buf off |> put_len (len * (List.length l)) buf in
    List.fold_left f off l
  in
  let put_coded_8_list ?min_len code l buf off =
    make_listf ?min_len (fun off x -> put_8 x buf off) 1 code l buf off in
  (* let put_coded_32_list = make_listf (fun buf x -> put_32 x buf) 4 in *)
  let put_coded_ip_list ?min_len code l buf off =
    make_listf ?min_len (fun off x -> put_ip x buf off) 4 code l buf off in
  let put_coded_prefix_list ?min_len code l buf off =
    make_listf ?min_len (fun off x -> put_prefix x buf off) 8 code l buf off in
  let put_coded_ip_tuple_list ?min_len code l buf off =
    make_listf ?min_len (fun off x -> put_ip_tuple x buf off) 8 code l buf off in
  let put_coded_vi_vendor_thing code items buf off =
    if items = [] then invalid_arg "Invalid option";
    let len =
      List.fold_left (fun acc (_ent, data) -> acc + 4 + 1 + String.length data) 0 items
    in
    let off = put_code code buf off |> put_len len buf in
    List.fold_left (fun off (ent, data) ->
        let off = put_32 ent buf off in
        let len = String.length data in
        let off = put_len len buf off in
        Bytes.blit_string data 0 buf off len;
        off + len)
      off items
  in
  let put_coded_vi_vendor_info code items buf off =
    let items =
      List.map (fun (pen, sub_options) ->
          let sub_option (code, data) =
            let len = String.length data in
            if len > 255 then
              invalid_arg ("suboption len is too big: " ^ string_of_int len);
            let b = Bytes.create (2 + len) in
            Bytes.set_uint8 b 0 code;
            Bytes.set_uint8 b 1 len;
            Bytes.blit_string data 0 b 2 len;
            Bytes.unsafe_to_string b
          in
          (pen, String.concat "" (List.map sub_option sub_options)))
        items
    in
    put_coded_vi_vendor_thing code items buf off
  in
  let put_coded_vi_vendor_class code items buf off =
    let items =
      List.map (fun (pen, datas) ->
          pen,
          String.concat ""
            (List.map (fun data ->
                 let len = String.length data in
                 if len > 255 then
                   invalid_arg ("V-I vendor class data is too big: " ^ string_of_int len);
                 let b = Bytes.create (1 + len) in
                 Bytes.set_uint8 b 0 len;
                 Bytes.blit_string data 0 b 1 len;
                 Bytes.unsafe_to_string b)
                datas))
        items
    in
    put_coded_vi_vendor_thing code items buf off
  in
  let buf_of_option buf off option =
    match option with
    | Pad -> off (* we don't pad *)                           (* code 0 *)
    | Subnet_mask mask -> put_coded_ip 1 mask buf off             (* code 1 *)
    | Time_offset toff -> put_coded_32 2 toff buf off             (* code 2 *)
    | Routers ips -> put_coded_ip_list 3 ips buf off              (* code 3 *)
    | Dns_servers ips -> put_coded_ip_list 6 ips buf off          (* code 6 *)
    | Log_servers ips -> put_coded_ip_list 7 ips buf off          (* code 7 *)
    | Lpr_servers ips -> put_coded_ip_list 9 ips buf off          (* code 9 *)
    | Hostname h -> put_coded_bytes 12 h buf off                  (* code 12 *)
    | Bootfile_size bs -> put_coded_16 13 bs buf off              (* code 13 *)
    | Domain_name dn -> put_coded_bytes 15 dn buf off             (* code 15 *)
    | Swap_server ss -> put_coded_ip 16 ss buf off                (* code 16 *)
    | Root_path rp -> put_coded_bytes 17 rp buf off               (* code 17 *)
    | Extension_path ep -> put_coded_bytes 18 ep buf off          (* code 18 *)
    | Ipforwarding b -> put_coded_bool 19 b buf off               (* code 19 *)
    | Nlsr b -> put_coded_bool 20 b buf off                       (* code 20 *)
    | Policy_filters pf -> put_coded_prefix_list 21 pf buf off    (* code 21 *)
    | Max_datagram md -> put_coded_16 22 md buf off               (* code 22 *)
    | Default_ip_ttl dit -> put_coded_8 23 dit buf off            (* code 23 *)
    | Interface_mtu im -> put_coded_16 26 im buf off              (* code 26 *)
    | All_subnets_local b -> put_coded_bool 27 b buf off          (* code 27 *)
    | Broadcast_addr ba -> put_coded_ip 28 ba buf off             (* code 28 *)
    | Perform_router_disc b -> put_coded_bool 31 b buf off        (* code 31 *)
    | Router_sol_addr rsa -> put_coded_ip 32 rsa buf off          (* code 32 *)
    | Static_routes srs -> put_coded_ip_tuple_list 33 srs buf off (* code 33 *)
    | Trailer_encapsulation b -> put_coded_bool 34 b buf off      (* code 34 *)
    | Arp_cache_timo act -> put_coded_32 35 act buf off           (* code 35 *)
    | Ethernet_encapsulation b -> put_coded_bool 36 b buf off     (* code 36 *)
    | Tcp_default_ttl tdt -> put_coded_8 37 tdt buf off           (* code 37 *)
    | Tcp_keepalive_interval tki -> put_coded_32 38 tki buf off   (* code 38 *)
    | Nis_domain nd -> put_coded_bytes 40 nd buf off              (* code 40 *)
    | Nis_servers ips -> put_coded_ip_list 41 ips buf off         (* code 41 *)
    | Ntp_servers ips -> put_coded_ip_list 42 ips buf off         (* code 42 *)
    | Vendor_specific vs -> put_coded_bytes 43 vs buf off         (* code 43 *)
    | Netbios_name_servers ips -> put_coded_ip_list 44 ips buf off(* code 44 *)
    | Netbios_datagram_distrib_servers ips -> put_coded_ip_list 45 ips buf off (* code 45 *)
    | Netbios_node nn -> put_coded_8 46 nn buf off                (* code 46 *)
    | Netbios_scope ns -> put_coded_bytes 47 ns buf off           (* code 47 *)
    | Xwindow_font_servers ips -> put_coded_ip_list 48 ips buf off(* code 48 *)
    | Xwindow_display_managers ips -> put_coded_ip_list 49 ips buf off (* code 49 *)
    | Request_ip rip -> put_coded_ip 50 rip buf off               (* code 50 *)
    | Ip_lease_time ilt -> put_coded_32 51 ilt buf off            (* code 51 *)
    | Option_overload oo -> put_coded_8 52 oo buf off             (* code 52 *)
    | Message_type mt -> put_coded_8 53 (msgtype_to_int mt) buf off (* code 53 *)
    | Server_identifier si -> put_coded_ip 54 si buf off          (* code 54 *)
    | Parameter_requests pr ->
      put_coded_8_list 55
        (List.map option_code_to_int pr) buf off                  (* code 55 *)
    | Message m -> put_coded_bytes 56 m buf off                   (* code 56 *)
    | Max_message mm -> put_coded_16 57 mm buf off                (* code 57 *)
    | Renewal_t1 rt -> put_coded_32 58 rt buf off                 (* code 58 *)
    | Rebinding_t2 rt -> put_coded_32 59 rt buf off               (* code 59 *)
    | Vendor_class_id vci -> put_coded_bytes 60 vci buf off       (* code 60 *)
    | Client_id id -> put_client_id 61 id buf off                 (* code 61 *)
    | Nis_plus_domain npd -> put_coded_bytes 64 npd buf off       (* code 64 *)
    | Nis_plus_servers ips -> put_coded_ip_list 65 ips buf off    (* code 65 *)
    | Tftp_server_name tsn -> put_coded_bytes 66 tsn buf off      (* code 66 *)
    | Bootfile_name bn -> put_coded_bytes 67 bn buf off           (* code 67 *)
    | Mobile_ip_home_agent ips -> put_coded_ip_list ~min_len:0 68 ips buf off (* code 68 *)
    | Smtp_servers ips -> put_coded_ip_list 69 ips buf off        (* code 69 *)
    | Pop3_servers ips -> put_coded_ip_list 70 ips buf off        (* code 70 *)
    | Nntp_servers ips -> put_coded_ip_list 71 ips buf off        (* code 71 *)
    | Irc_servers ips -> put_coded_ip_list 74 ips buf off         (* code 74 *)
    | User_class uc -> put_coded_bytes 77 uc buf off              (* code 77 *)
    | Rapid_commit -> put_coded_bytes 80 "" buf off               (* code 80 *)
    | Client_fqdn dn -> put_client_fqdn 81 dn buf off             (* code 81 *)
    | Relay_agent_information ai -> put_coded_bytes 82 ai buf off (* code 82 *)
    | Client_system cs -> put_coded_bytes 93 cs buf off           (* code 93 *)
    | Client_ndi ndi -> put_coded_bytes 94 ndi buf off            (* code 94 *)
    | Uuid_guid u -> put_coded_bytes 97 u buf off                 (* code 97 *)
    | Pcode p -> put_coded_bytes 100 p buf off                    (* code 100 *)
    | Tcode t -> put_coded_bytes 101 t buf off                    (* code 101 *)
    | IPv6_only ts -> put_coded_32 108 ts buf off                 (* code 108 *)
    | Subnet_selection ip -> put_coded_ip 118 ip buf off          (* code 118 *)
    | Domain_search s -> put_coded_bytes 119 s buf off            (* code 119 *)
    | Sip_servers ss -> put_coded_bytes 120 ss buf off            (* code 120 *)
    | Classless_static_route r -> put_coded_bytes 121 r buf off   (* code 121 *) (* XXX current, use better type *)
    | Vi_vendor_class vi -> put_coded_vi_vendor_class 124 vi buf off (* code 124 *)
    | Vi_vendor_info vi -> put_coded_vi_vendor_info 125 vi buf off (* code 125 *)
    | Misc_150 s -> put_coded_bytes 150 s buf off                 (* code 150 *)
    | Private_classless_static_route r -> put_coded_bytes 249 r buf off (* code 249 *) (* XXX current, use better type *)
    | Web_proxy_auto_disc wpad -> put_coded_bytes 252 wpad buf off (* code 252 *)
    | Other (code, s) -> put_coded_bytes code s buf off (* unassigned *)
    | End -> off (* discard, we add ourselves *)              (* code 255 *)
  in
  match options with
  | [] -> invalid_arg "Invalid options"
  | _ ->
    let () = Bytes.set_int32_be sbuf 0 0x63825363l in       (* put cookie *)
    let off' = List.fold_left (buf_of_option sbuf) 4 options in
    Bytes.set_uint8 sbuf off' (option_code_to_int END);
    off' + 1

let pkt_of_buf buf len =
  let wrap () =
    let test = len >= sizeof_ethernet + sizeof_ipv4 + sizeof_udp + sizeof_dhcp in
    let* () = guard test `Not_dhcp in
    (* check if it's IPv4 protocol ([0x0800]) *)
    let* () = guard (String.get_uint16_be buf 12 = 0x0800) `Not_dhcp in
    (* Ethernet layer *)
    let dstmac = Macaddr.of_octets_exn (String.sub buf 0 6) in
    let srcmac = Macaddr.of_octets_exn (String.sub buf 6 6) in
    (* IP layer *)
    let ihl = String.get_uint8 buf sizeof_ethernet land 0x0f in
    let* () = guard (ihl >= 5) `Not_dhcp in
    let ip_hdr_len = ihl * 4 in
    (* check if it's UDP protocol ([17]) *)
    let* () = guard (String.get_uint8 buf (sizeof_ethernet + 9) = 17) `Not_dhcp in
    let srcip = Ipaddr.V4.of_int32 (String.get_int32_be buf (sizeof_ethernet + 12)) in
    let dstip = Ipaddr.V4.of_int32 (String.get_int32_be buf (sizeof_ethernet + 16)) in
    (* UDP layer *)
    let udp_off = sizeof_ethernet + ip_hdr_len in
    let srcport = String.get_uint16_be buf (udp_off + 0) in
    let dstport = String.get_uint16_be buf (udp_off + 2) in
    let udp_len = String.get_uint16_be buf (udp_off + 4) in
    let chk = String.get_uint16_be buf (udp_off + 6) in
    (* NOTE(dinosaure): compute the checksum only if [chk <> 0]. *)
    let* () = if chk = 0 then Ok ()
      else begin
        let ph = Bytes.create 12 in
        Bytes.set_int32_be ph 0 (Ipaddr.V4.to_int32 srcip);
        Bytes.set_int32_be ph 4 (Ipaddr.V4.to_int32 dstip);
        Bytes.set_uint8 ph 8 0;
        Bytes.set_uint8 ph 9 17;
        Bytes.set_uint16_be ph 10 udp_len;
        let seg = String.sub buf udp_off udp_len in
        let chk' = 0 in
        let chk' = Chk.add chk' (Bytes.unsafe_to_string ph) in
        let chk' = Chk.add chk' seg in
        guard (Chk.get chk' = 0) `Not_dhcp
      end in
    let dhcp_off = udp_off + sizeof_udp in
    (* DHCP layer *)
    let* op = int_to_op (get_dhcp_op buf dhcp_off) |> Option.to_result ~none:`Not_dhcp in
    let htype = if (get_dhcp_htype buf dhcp_off) = 1 then
        Ethernet_10mb
      else
        Other
    in
    let hlen = get_dhcp_hlen buf dhcp_off in
    let hops = get_dhcp_hops buf dhcp_off in
    let xid = get_dhcp_xid buf dhcp_off in
    let secs = get_dhcp_secs buf dhcp_off in
    let flags =
      if ((get_dhcp_flags buf dhcp_off) land 0x8000) <> 0 then Broadcast else Unicast
    in
    let ciaddr = Ipaddr.V4.of_int32 (get_dhcp_ciaddr buf dhcp_off) in
    let yiaddr = Ipaddr.V4.of_int32 (get_dhcp_yiaddr buf dhcp_off) in
    let siaddr = Ipaddr.V4.of_int32 (get_dhcp_siaddr buf dhcp_off) in
    let giaddr = Ipaddr.V4.of_int32 (get_dhcp_giaddr buf dhcp_off) in
    let* chaddr =
      if htype = Ethernet_10mb && hlen = 6 then
        Ok (Macaddr.of_octets_exn (copy_dhcp_chaddr buf dhcp_off))
      else
        Error `Not_dhcp
    in
    let sname = cstruct_copy_normalized (copy_dhcp_sname buf) dhcp_off in
    let file = cstruct_copy_normalized (copy_dhcp_file buf) dhcp_off in
    let options =
      options_of_buf buf (dhcp_off + sizeof_dhcp) (String.length buf - (dhcp_off + sizeof_dhcp))
    in
    Ok { srcmac; dstmac; srcip; dstip; srcport; dstport;
         op; htype; hlen; hops; xid; secs; flags; ciaddr; yiaddr;
         siaddr; giaddr; chaddr; sname; file; options }
  in
  try wrap () with | Invalid_argument _ -> Error `Not_dhcp

let pkt_into_buf pkt buf =
  let ip_off = sizeof_ethernet in
  let udp_off = sizeof_ethernet + sizeof_ipv4 in
  let dhcp_off = sizeof_ethernet + sizeof_ipv4 + sizeof_udp in
  set_dhcp_op buf dhcp_off (op_to_int pkt.op);
  set_dhcp_htype buf dhcp_off
    (if pkt.htype = Ethernet_10mb then
       1
     else
       invalid_arg "Can only build Ethernet_10mb");
  set_dhcp_hlen buf dhcp_off pkt.hlen;
  set_dhcp_hops buf dhcp_off pkt.hops;
  set_dhcp_xid buf dhcp_off pkt.xid;
  set_dhcp_secs buf dhcp_off pkt.secs;
  set_dhcp_flags buf dhcp_off (if pkt.flags = Broadcast then 0x8000 else 0);
  set_dhcp_ciaddr buf dhcp_off (Ipaddr.V4.to_int32 pkt.ciaddr);
  set_dhcp_yiaddr buf dhcp_off (Ipaddr.V4.to_int32 pkt.yiaddr);
  set_dhcp_siaddr buf dhcp_off (Ipaddr.V4.to_int32 pkt.siaddr);
  set_dhcp_giaddr buf dhcp_off (Ipaddr.V4.to_int32 pkt.giaddr);
  set_dhcp_chaddr (string_extend_if_le (Macaddr.to_octets pkt.chaddr) 16) 0 buf dhcp_off;
  set_dhcp_sname (string_extend_if_le pkt.sname 64) 0 buf dhcp_off;
  set_dhcp_file (string_extend_if_le pkt.file 128) 0 buf dhcp_off;
  let options_start = String.sub buf (dhcp_off + sizeof_dhcp) (String.length buf - (dhcp_off + sizeof_dhcp)) in
  let options_end = buf_of_options options_start pkt.options in
  let partial_len = Cstruct.length dhcp - Cstruct.length options_end in
  let buf_end =
    let pad_len = 300 - partial_len in
    if pad_len > 0 then begin
      for i = 0 to pad_len do
        Cstruct.set_uint8 options_end i 0
      done;
      Cstruct.shift options_end pad_len
    end else
      options_end
  in
  let dhcp = Cstruct.sub dhcp 0 (Cstruct.length dhcp - Cstruct.length buf_end) in
  let dhcp_len = Cstruct.length dhcp in
  (* Ethernet *)
  Cstruct.blit_from_string (Macaddr.to_octets pkt.dstmac) 0 eth 0 6;
  Cstruct.blit_from_string (Macaddr.to_octets pkt.srcmac) 0 eth 6 6;
  Cstruct.BE.set_uint16 eth 12 0x0800; (* IPv4 protocol *)
  (* UDP *)
  Cstruct.BE.set_uint16 udp 0 pkt.srcport;
  Cstruct.BE.set_uint16 udp 2 pkt.dstport;
  Cstruct.BE.set_uint16 udp 4 (sizeof_udp + dhcp_len);
  Cstruct.BE.set_uint16 udp 6 0;
  (* IP *)
  Cstruct.set_uint8 ip 0 0x45; (* IHL = (version 4) | (len = 5) *)
  Cstruct.set_uint8 ip 1 0;
  Cstruct.BE.set_uint16 ip 2 (sizeof_ipv4 + sizeof_udp + dhcp_len);
  Cstruct.BE.set_uint16 ip 4 0;
  Cstruct.BE.set_uint16 ip 6 0;
  Cstruct.set_uint8 ip 8 255; (* TTL *)
  Cstruct.set_uint8 ip 9 17; (* UDP protocol *)
  Cstruct.BE.set_uint16 ip 10 0;
  Cstruct.BE.set_uint32 ip 12 (Ipaddr.V4.to_int32 pkt.srcip);
  Cstruct.BE.set_uint32 ip 16 (Ipaddr.V4.to_int32 pkt.dstip);
  Cstruct.BE.set_uint16 ip 10 (Chk.get (Chk.add 0 ip));
  (* UDP checksum *)
  let ph = Cstruct.create 12 in
  Cstruct.BE.set_uint32 ph 0 (Ipaddr.V4.to_int32 pkt.srcip);
  Cstruct.BE.set_uint32 ph 4 (Ipaddr.V4.to_int32 pkt.dstip);
  Cstruct.set_uint8 ph 8 0;
  Cstruct.set_uint8 ph 9 17; (* UDP protocol *)
  Cstruct.BE.set_uint16 ph 10 (sizeof_udp + dhcp_len);
  let chk = 0 in
  let chk = Chk.add chk ph in
  let chk = Chk.add chk udp in
  let chk = Chk.add chk dhcp in
  let chk = Chk.get chk in
  Cstruct.BE.set_uint16 udp 6 chk;
  sizeof_ethernet + sizeof_ipv4 + sizeof_udp + dhcp_len

let buf_of_pkt pkg =
  (* TODO mtu *)
  let dhcp = Bytes.create 2048 in
  let l = pkt_into_buf pkg dhcp in
  Bytes.sub_string dhcp 0 l

let is_dhcp buf _len =
  try
    if String.get_uint16_be buf 12 <> 0x0800 then false
    else
      if String.get_uint8 buf (sizeof_ethernet + 9) <> 17 then false
      else
        let ihl = String.get_uint8 buf sizeof_ethernet land 0x0f in
        let udp_off = sizeof_ethernet + (ihl * 4) in
        let srcport = String.get_uint16_be buf (udp_off + 0) in
        let dstport = String.get_uint16_be buf (udp_off + 2) in
        (dstport = server_port || dstport = client_port)
        && (srcport = server_port || srcport = client_port)
  with Invalid_argument _ -> false

let collect_options f options = filter_map f options |> List.flatten

let client_id_of_pkt pkt =
  match find_option
          (function Client_id id -> Some id | _ -> None)
          pkt.options
  with
  | Some id -> id
  | None -> Hwaddr pkt.chaddr

let find_subnet_mask =
  find_option (function Subnet_mask x -> Some x | _ -> None)
let find_time_offset =
  find_option (function Time_offset x -> Some x | _ -> None)
let collect_routers =
  collect_options (function Routers x -> Some x | _ -> None)
let collect_dns_servers =
  collect_options (function Dns_servers x -> Some x | _ -> None)
let collect_log_servers =
  collect_options (function Log_servers x -> Some x | _ -> None)
let collect_lpr_servers =
  collect_options (function Lpr_servers x -> Some x | _ -> None)
let find_hostname =
  find_option (function Hostname x -> Some x | _ -> None)
let find_bootfile_size =
  find_option (function Bootfile_size x -> Some x | _ -> None)
let find_domain_name =
  find_option (function Domain_name x -> Some x | _ -> None)
let find_swap_server =
  find_option (function Swap_server x -> Some x | _ -> None)
let find_root_path =
  find_option (function Root_path x -> Some x | _ -> None)
let find_extension_path =
  find_option (function Extension_path x -> Some x | _ -> None)
let find_ipforwarding =
  find_option (function Ipforwarding x -> Some x | _ -> None)
let find_nlsr =
  find_option (function Nlsr x -> Some x | _ -> None)
let collect_policy_filters =
  collect_options (function Policy_filters x -> Some x | _ -> None)
let find_max_datagram =
  find_option (function Max_datagram x -> Some x | _ -> None)
let find_default_ip_ttl =
  find_option (function Default_ip_ttl x -> Some x | _ -> None)
let find_interface_mtu =
  find_option (function Interface_mtu x -> Some x | _ -> None)
let find_all_subnets_local =
  find_option (function All_subnets_local x -> Some x | _ -> None)
let find_broadcast_addr =
  find_option (function Broadcast_addr x -> Some x | _ -> None)
let find_perform_router_disc =
  find_option (function Perform_router_disc x -> Some x | _ -> None)
let find_router_sol_addr =
  find_option (function Router_sol_addr x -> Some x | _ -> None)
let collect_static_routes =
  collect_options (function Static_routes x -> Some x | _ -> None)
let find_trailer_encapsulation =
  find_option (function Trailer_encapsulation x -> Some x | _ -> None)
let find_arp_cache_timo =
  find_option (function Arp_cache_timo x -> Some x | _ -> None)
let find_ethernet_encapsulation =
  find_option (function Ethernet_encapsulation x -> Some x | _ -> None)
let find_tcp_default_ttl =
  find_option (function Tcp_default_ttl x -> Some x | _ -> None)
let find_tcp_keepalive_interval =
  find_option (function Tcp_keepalive_interval x -> Some x | _ -> None)
let find_nis_domain =
  find_option (function Nis_domain x -> Some x | _ -> None)
let collect_nis_servers =
  collect_options (function Nis_servers x -> Some x | _ -> None)
let collect_ntp_servers =
  collect_options (function Ntp_servers x -> Some x | _ -> None)
let find_vendor_specific =
  find_option (function Vendor_specific x -> Some x | _ -> None)
let collect_netbios_name_servers =
  collect_options (function Netbios_name_servers x -> Some x | _ -> None)
let collect_netbios_datagram_distrib_servers =
  collect_options (function Netbios_datagram_distrib_servers x -> Some x | _ -> None)
let find_netbios_node =
  find_option (function Netbios_node x -> Some x | _ -> None)
let find_netbios_scope =
  find_option (function Netbios_scope x -> Some x | _ -> None)
let collect_xwindow_font_servers =
  collect_options (function Xwindow_font_servers x -> Some x | _ -> None)
let collect_xwindow_display_managers =
  collect_options (function Xwindow_display_managers x -> Some x | _ -> None)
let find_request_ip =
  find_option (function Request_ip x -> Some x | _ -> None)
let find_ip_lease_time =
  find_option (function Ip_lease_time x -> Some x | _ -> None)
let find_option_overload =
  find_option (function Option_overload x -> Some x | _ -> None)
let find_message_type =
  find_option (function Message_type x -> Some x | _ -> None)
let find_server_identifier =
  find_option (function Server_identifier x -> Some x | _ -> None)
let find_parameter_requests =
  find_option (function Parameter_requests x -> Some x | _ -> None)
let find_message =
  find_option (function Message x -> Some x | _ -> None)
let find_max_message =
  find_option (function Max_message x -> Some x | _ -> None)
let find_renewal_t1 =
  find_option (function Renewal_t1 x -> Some x | _ -> None)
let find_rebinding_t2 =
  find_option (function Rebinding_t2 x -> Some x | _ -> None)
let find_vendor_class_id =
  find_option (function Vendor_class_id x -> Some x | _ -> None)
let find_client_id =
  find_option (function Client_id x -> Some x | _ -> None)
let find_nis_plus_domain =
  find_option (function Nis_plus_domain x -> Some x | _ -> None)
let collect_nis_plus_servers =
  collect_options (function Nis_plus_servers x -> Some x | _ -> None)
let find_tftp_server_name =
  find_option (function Tftp_server_name x -> Some x | _ -> None)
let find_bootfile_name =
  find_option (function Bootfile_name x -> Some x | _ -> None)
let collect_mobile_ip_home_agent =
  collect_options (function Mobile_ip_home_agent x -> Some x | _ -> None)
let collect_smtp_servers =
  collect_options (function Smtp_servers x -> Some x | _ -> None)
let collect_pop3_servers =
  collect_options (function Pop3_servers x -> Some x | _ -> None)
let collect_nntp_servers =
  collect_options (function Nntp_servers x -> Some x | _ -> None)
let collect_irc_servers =
  collect_options (function Irc_servers x -> Some x | _ -> None)
let find_user_class =
  find_option (function User_class x -> Some x | _ -> None)
let find_rapid_commit =
  find_option (function Rapid_commit -> Some Rapid_commit | _ -> None)
let find_client_fqdn =
  find_option (function Client_fqdn x -> Some x | _ -> None)
let find_relay_agent_information =
  find_option (function Relay_agent_information x -> Some x | _ -> None)
let find_client_system =
  find_option (function Client_system x -> Some x | _ -> None)
let find_client_ndi =
  find_option (function Client_ndi x -> Some x | _ -> None)
let find_uuid_guid =
  find_option (function Uuid_guid x -> Some x | _ -> None)
let find_pcode =
  find_option (function Pcode x -> Some x | _ -> None)
let find_tcode =
  find_option (function Tcode x -> Some x | _ -> None)
let find_ipv6only =
  find_option (function IPv6_only x -> Some x | _ -> None)
let find_subnet_selection =
  find_option (function Subnet_selection x -> Some x | _ -> None)
let find_domain_search =
  find_option (function Domain_search x -> Some x | _ -> None)
let find_sip_servers =
  find_option (function Sip_servers x -> Some x | _ -> None)
let find_classless_static_route =
  find_option (function Classless_static_route x -> Some x | _ -> None)
let collect_vi_vendor_class =
  collect_options (function Vi_vendor_class x -> Some x | _ -> None)
let collect_vi_vendor_info =
  collect_options (function Vi_vendor_info x -> Some x | _ -> None)
let find_misc_150 =
  find_option (function Misc_150 x -> Some x | _ -> None)
let find_web_proxy_auto_disc =
  find_option (function Web_proxy_auto_disc x -> Some x | _ -> None)
let find_private_classless_static_route =
  find_option (function Private_classless_static_route x -> Some x | _ -> None)
let find_other code =
  find_option (function Other (c, s) when c = code -> Some (c, s) | _ -> None)
let collect_other code =
  collect_options (function Other (c, s) when c = code -> Some [(c, s)] | _ -> None)
