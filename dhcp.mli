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

type op =
  | Bootrequest
  | Bootreply
  | Unknown with sexp

type htype =
  | Ethernet_10mb
  | Other with sexp

type flags =
  | Broadcast
  | Unicast with sexp

type chaddr =
  | Hwaddr of Macaddr.t
  | Cliid of string with sexp

type msgtype =
  | DHCPDISCOVER (* value 1 *)
  | DHCPOFFER    (* value 2 *)
  | DHCPREQUEST  (* value 3 *)
  | DHCPDECLINE  (* value 4 *)
  | DHCPACK      (* value 5 *)
  | DHCPNAK      (* value 6 *)
  | DHCPRELEASE  (* value 7 *)
  | DHCPINFORM   (* value 8 *)
  with sexp

type parameter_request =
  | Subnet_mask                      (* code 1 *)
  | Time_offset                      (* code 2 *)
  | Routers                          (* code 3 *)
  | Time_servers                     (* code 4 *)
  | Name_servers                     (* code 5 *)
  | Dns_servers                      (* code 6 *)
  | Log_servers                      (* code 7 *)
  | Cookie_servers                   (* code 8 *)
  | Lpr_servers                      (* code 9 *)
  | Impress_servers                  (* code 10 *)
  | Rsclocation_servers              (* code 11 *)
  | Hostname                         (* code 12 *)
  | Bootfile_size                    (* code 13 *)
  | Merit_dumpfile                   (* code 14 *)
  | Domain_name                      (* code 15 *)
  | Swap_server                      (* code 16 *)
  | Root_path                        (* code 17 *)
  | Extension_path                   (* code 18 *)
  | Ipforwarding                     (* code 19 *)
  | Nlsr                             (* code 20 *)
  | Policy_filters                   (* code 21 *)
  | Max_datagram                     (* code 22 *)
  | Default_ip_ttl                   (* code 23 *)
  | Pmtu_ageing_timo                 (* code 24 *)
  | Pmtu_plateau_table               (* code 25 *)
  | Interface_mtu                    (* code 26 *)
  | All_subnets_local                (* code 27 *)
  | Broadcast_addr                   (* code 28 *)
  | Perform_mask_discovery           (* code 29 *)
  | Mask_supplier                    (* code 30 *)
  | Perform_router_disc              (* code 31 *)
  | Router_sol_addr                  (* code 32 *)
  | Static_routes                    (* code 33 *)
  | Trailer_encapsulation            (* code 34 *)
  | Arp_cache_timo                   (* code 35 *)
  | Ethernet_encapsulation           (* code 36 *)
  | Tcp_default_ttl                  (* code 37 *)
  | Tcp_keepalive_interval           (* code 38 *)
  | Tcp_keepalive_garbage            (* code 39 *)
  | Nis_domain                       (* code 40 *)
  | Nis_servers                      (* code 41 *)
  | Ntp_servers                      (* code 42 *)
  | Vendor_specific                  (* code 43 *)
  | Netbios_name_servers             (* code 44 *)
  | Netbios_datagram_distrib_servers (* code 45 *)
  | Netbios_node                     (* code 46 *)
  | Netbios_scope                    (* code 47 *)
  | Xwindow_font_servers             (* code 48 *)
  | Xwindow_display_managers         (* code 49 *)
  | Request_ip                       (* code 50 *)
  | Ip_lease_time                    (* code 51 *)
  | Option_overload                  (* code 52 *)
  | Message_type                     (* code 53 *)
  | Server_identifier                (* code 54 *)
  | Parameter_requests               (* code 55 *)
  | Message                          (* code 56 *)
  | Max_message                      (* code 57 *)
  | Renewal_t1                       (* code 58 *)
  | Rebinding_t2                     (* code 59 *)
  | Vendor_class_id                  (* code 60 *)
  | Client_id                        (* code 61 *)
  | Nis_plus_domain                  (* code 64 *)
  | Nis_plus_servers                 (* code 65 *)
  | Tftp_server_name                 (* code 66 *)
  | Bootfile_name                    (* code 67 *)
  | Mobile_ip_home_agent             (* code 68 *)
  | Smtp_servers                     (* code 69 *)
  | Pop3_servers                     (* code 70 *)
  | Nntp_servers                     (* code 71 *)
  | Www_servers                      (* code 72 *)
  | Finger_servers                   (* code 73 *)
  | Irc_servers                      (* code 74 *)
  | Streettalk_servers               (* code 75 *)
  | Streettalk_da                    (* code 76 *)
  | Unknown of int
  with sexp

val parameter_request_of_int : int -> parameter_request
val int_of_parameter_request : parameter_request -> int

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
  | Policy_filters of Ipaddr.V4.Prefix.t list (* code 21 *)
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
  | Static_routes of Ipaddr.V4.Prefix.t list(* code 33 *)
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
  | Message_type of msgtype                 (* code 53 *)
  | Server_identifier of Ipaddr.V4.t        (* code 54 *)
  | Parameter_requests of parameter_request list (* code 55 *)
  | Message of string                       (* code 56 *)
  | Max_message of int                      (* code 57 *)
  | Renewal_t1 of Int32.t                   (* code 58 *)
  | Rebinding_t2 of Int32.t                 (* code 59 *)
  | Vendor_class_id of string               (* code 60 *)
  | Client_id of chaddr                     (* code 61 *)
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
  with sexp

(* Describes a packed DHCP packet *)
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
} with sexp

val pkt_min_len : int
val make_buf : unit -> Cstruct.t
val pkt_of_buf : Cstruct.t -> int -> pkt
val client_id_of_pkt : pkt -> chaddr
val str_of_pkt : pkt -> string
val str_of_msgtype : msgtype -> string
val msgtype_of_options : dhcp_option list -> msgtype option
val parameter_requests_of_options : dhcp_option list -> parameter_request list option
val request_ip_of_options : dhcp_option list -> Ipaddr.V4.t option
val ip_lease_time_of_options : dhcp_option list -> int32 option

(* Lease (dhcp bindings) operations *)
type lease = {
  tm_start   : float;
  tm_end     : float;
  addr       : Ipaddr.V4.t;
  client_id  : chaddr;
  hostname   : string;
} with sexp

(* opaque *)
type leases with sexp

val create_leases : unit -> leases
val lookup_lease : chaddr -> leases -> lease option
val replace_lease : chaddr -> lease -> leases -> unit
val lease_expired : lease -> bool
val str_of_lease : lease -> string

val addr_in_range : Ipaddr.V4.t -> (Ipaddr.V4.t * Ipaddr.V4.t) -> bool
val addr_available : Ipaddr.V4.t -> leases -> bool

val get_usable_addr : chaddr -> (Ipaddr.V4.t * Ipaddr.V4.t) -> leases ->
  Ipaddr.V4.t option
