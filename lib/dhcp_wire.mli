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

(** {2 DHCP general data} *)

val client_port : int
(** DHCP client port [68] *)

val server_port : int
(** DHCP server port [67] *)

(** {2 DHCP header opcodes} *)

type op =
  | BOOTREQUEST
  | BOOTREPLY

(** Conversions of {! op}s. *)

val int_to_op : int -> op option

val int_to_op_exn : int -> op (** @raise Invalid_argument if [v < 0 || v > 255]  *)

val op_to_int : op -> int

val op_to_string : op -> string

(** {2 DHCP message type option values} *)

type msgtype =
  | DHCPDISCOVER
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

(** Conversions of {! msgtype}s. *)

val msgtype_to_int : msgtype -> int
val int_to_msgtype : int -> msgtype option
val int_to_msgtype_exn : int -> msgtype
(** @raise Invalid_argument if not a valid {! msgtype} value *)

val msgtype_to_string : msgtype -> string

(** {2 DHCP option codes (names only, for use in parameter requests)} *)

type option_code =
  | PAD
  | SUBNET_MASK
  | TIME_OFFSET
  | ROUTERS
  | DNS_SERVERS
  | LOG_SERVERS
  | LPR_SERVERS
  | HOSTNAME
  | BOOTFILE_SIZE
  | DOMAIN_NAME
  | SWAP_SERVER
  | ROOT_PATH
  | EXTENSION_PATH
  | IPFORWARDING
  | NLSR
  | POLICY_FILTERS
  | MAX_DATAGRAM
  | DEFAULT_IP_TTL
  | INTERFACE_MTU
  | ALL_SUBNETS_LOCAL
  | BROADCAST_ADDR
  | PERFORM_ROUTER_DISC
  | ROUTER_SOL_ADDR
  | STATIC_ROUTES
  | TRAILER_ENCAPSULATION
  | ARP_CACHE_TIMO
  | ETHERNET_ENCAPSULATION
  | TCP_DEFAULT_TTL
  | TCP_KEEPALIVE_INTERVAL
  | NIS_DOMAIN
  | NIS_SERVERS
  | NTP_SERVERS
  | VENDOR_SPECIFIC
  | NETBIOS_NAME_SERVERS
  | NETBIOS_DATAGRAM_DISTRIB_SERVERS
  | NETBIOS_NODE
  | NETBIOS_SCOPE
  | XWINDOW_FONT_SERVERS
  | XWINDOW_DISPLAY_MANAGERS
  | REQUEST_IP
  | IP_LEASE_TIME
  | OPTION_OVERLOAD
  | MESSAGE_TYPE
  | SERVER_IDENTIFIER
  | PARAMETER_REQUESTS
  | MESSAGE
  | MAX_MESSAGE
  | RENEWAL_T1
  | REBINDING_T2
  | VENDOR_CLASS_ID
  | CLIENT_ID
  | NIS_PLUS_DOMAIN
  | NIS_PLUS_SERVERS
  | TFTP_SERVER_NAME
  | BOOTFILE_NAME
  | MOBILE_IP_HOME_AGENT
  | SMTP_SERVERS
  | POP3_SERVERS
  | NNTP_SERVERS
  | IRC_SERVERS
  | USER_CLASS
  | RAPID_COMMIT
  | CLIENT_FQDN
  | RELAY_AGENT_INFORMATION
  | CLIENT_SYSTEM
  | CLIENT_NDI
  | UUID_GUID
  | PCODE
  | TCODE
  | IPV6ONLY
  | SUBNET_SELECTION
  | DOMAIN_SEARCH
  | SIP_SERVERS
  | CLASSLESS_STATIC_ROUTE
  | VI_VENDOR_CLASS
  | VI_VENDOR_INFO
  | MISC_150
  | PRIVATE_CLASSLESS_STATIC_ROUTE
  | WEB_PROXY_AUTO_DISC
  | END
  | OTHER of int
(** The type of a dhcp parameter request, these are all the values according to
    {{:https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml}iana}
*)

(** Conversions of DHCP {! option_code}s. *)

val int_to_option_code : int -> option_code option
val int_to_option_code_exn : int -> option_code
val option_code_to_int : option_code -> int
val option_code_to_string : option_code -> string

(** {2 DHCP hardware type} *)

type htype =
  | Ethernet_10mb
  | Other

(** Conversions of {!htype}. *)

val htype_to_string : htype -> string

(** {2 DHCP header flags} *)

type flags =
  | Broadcast
  | Unicast

(** Conversions of {!flags}. *)

val flags_to_string : flags -> string

(** {2 DHCP Client identifier} *)

type client_id =
  | Hwaddr of Macaddr.t
  | Id of int * string
(** A client_id is usually a mac address from a {! dhcp_option},
    but it can also be an opaque string. See {! client_id_of_pkt}. *)

(** Conversions of {! client_id}. *)

val client_id_to_string : client_id -> string
val string_to_client_id : string -> client_id option

type client_fqdn =
  [ `Server_A (* C2S server should register A in DNS *)
  | `Overriden (* S2C DNS entry was overriden *)
  | `No_update (* C2S should not do any DNS updates *)
  | `Wire_encoding (* both, if not set some deprecated ASCII encoding *)
  ] list *
  (* rcode_1 and rcode_2, both ignored *)
  [ `raw ] Domain_name.t
(** A client_fqdn is some flags, and a domain name. *)

(** Conversions of {! client_fqdn}. *)

val client_fqdn_to_string : client_fqdn -> string
val string_to_client_fqdn : string -> client_fqdn

(** {2 DHCP options} *)

type dhcp_option =
  | Pad                                     (* code 0 *)
  | Subnet_mask of Ipaddr.V4.t              (* code 1 *)
  | Time_offset of int32                    (* code 2 *)
  | Routers of Ipaddr.V4.t list             (* code 3 *)
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
  | Subnet_selection of Ipaddr.V4.t         (* code 118 *)
  | Domain_search of string                 (* code 119 *)
  | Sip_servers of string                   (* code 120 *)
  | Classless_static_route of string        (* code 121 *) (* XXX current, use better type *)
  | Vi_vendor_class of                      (* code 124 *)
      (int32 * string) list
  | Vi_vendor_info of                       (* code 125 *)
      (int32 * (int * string) list) list
  (** Vendor-identifying vendor information. It's a non-empty list of pairs of
      enterprise numbers and suboptions. The sub options is a pair of a u8
      (0-255) and sub-option data *)
  | Misc_150 of string                      (* code 150 *)
  | Private_classless_static_route of string(* code 249 *) (* XXX current, use better type *)
  | Web_proxy_auto_disc of string           (* code 252 *)
  | End                                     (* code 255 *)
  | Other of int * string              (* int * string *)
(** Not all options are currently implemented. *)

(** Conversions of {! dhcp_option}. *)

val dhcp_option_to_string : dhcp_option -> string

val buf_of_options : Cstruct.t -> dhcp_option list -> Cstruct.t
val options_of_buf : Cstruct.t -> int -> dhcp_option list

val find_option : (dhcp_option -> 'b option) -> dhcp_option list -> 'b option
(** [find_option f l] finds the first option where [f] evaluates to [Some] value
    on list [l] *)

val collect_options : ('a -> 'b list option) -> 'a list -> 'b list
(** [collect_options f l] collects all options where [f] evaluates to [Some]
    value on list [l], this is useful for list options like [Routers], if
    multiple list options are found, the resulting list is flattened. *)

val collect_dns_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_irc_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_log_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_lpr_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_netbios_datagram_distrib_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_netbios_name_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_nis_plus_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_nis_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_ntp_servers : dhcp_option list -> Ipaddr.V4.t list
val find_parameter_requests : dhcp_option list -> option_code list option
val collect_policy_filters : dhcp_option list -> Ipaddr.V4.Prefix.t list
val collect_routers : dhcp_option list -> Ipaddr.V4.t list
val collect_static_routes : dhcp_option list -> (Ipaddr.V4.t * Ipaddr.V4.t) list
val collect_xwindow_display_managers : dhcp_option list -> Ipaddr.V4.t list
val collect_xwindow_font_servers : dhcp_option list -> Ipaddr.V4.t list
val find_all_subnets_local : dhcp_option list -> bool option
val find_arp_cache_timo : dhcp_option list -> int32 option
val find_bootfile_name : dhcp_option list -> string option
val find_bootfile_size : dhcp_option list -> int option
val find_broadcast_addr : dhcp_option list -> Ipaddr.V4.t option
val find_classless_static_route : dhcp_option list -> string option
val find_client_fqdn : dhcp_option list -> client_fqdn option
val find_client_id : dhcp_option list -> client_id option
val find_client_ndi : dhcp_option list -> string option
val find_client_system : dhcp_option list -> string option
val find_default_ip_ttl : dhcp_option list -> int option
val find_domain_name : dhcp_option list -> string option
val find_domain_search : dhcp_option list -> string option
val find_ethernet_encapsulation : dhcp_option list -> bool option
val find_extension_path : dhcp_option list -> string option
val find_hostname : dhcp_option list -> string option
val find_interface_mtu : dhcp_option list -> int option
val find_ip_lease_time : dhcp_option list -> int32 option
val find_ipforwarding : dhcp_option list -> bool option
val find_max_datagram : dhcp_option list -> int option
val find_max_message : dhcp_option list -> int option
val find_message : dhcp_option list -> string option
val find_message_type : dhcp_option list -> msgtype option
val find_misc_150 : dhcp_option list -> string option
val collect_mobile_ip_home_agent : dhcp_option list -> Ipaddr.V4.t list
val find_netbios_node : dhcp_option list -> int option
val find_netbios_scope : dhcp_option list -> string option
val find_nis_domain : dhcp_option list -> string option
val find_nis_plus_domain : dhcp_option list -> string option
val find_nlsr : dhcp_option list -> bool option
val collect_nntp_servers : dhcp_option list -> Ipaddr.V4.t list
val find_option_overload : dhcp_option list -> int option
val find_pcode : dhcp_option list -> string option
val find_perform_router_disc : dhcp_option list -> bool option
val collect_pop3_servers : dhcp_option list -> Ipaddr.V4.t list
val find_rapid_commit : dhcp_option list -> dhcp_option option
val find_rebinding_t2 : dhcp_option list -> int32 option
val find_relay_agent_information : dhcp_option list -> string option
val find_renewal_t1 : dhcp_option list -> int32 option
val find_request_ip : dhcp_option list -> Ipaddr.V4.t option
val find_root_path : dhcp_option list -> string option
val find_router_sol_addr : dhcp_option list -> Ipaddr.V4.t option
val find_server_identifier : dhcp_option list -> Ipaddr.V4.t option
val find_sip_servers : dhcp_option list -> string option
val collect_smtp_servers : dhcp_option list -> Ipaddr.V4.t list
val find_subnet_mask : dhcp_option list -> Ipaddr.V4.t option
val find_subnet_selection : dhcp_option list -> Ipaddr.V4.t option
val find_swap_server : dhcp_option list -> Ipaddr.V4.t option
val find_tcode : dhcp_option list -> string option
val find_ipv6only : dhcp_option list -> int32 option
val find_tcp_default_ttl : dhcp_option list -> int option
val find_tcp_keepalive_interval : dhcp_option list -> int32 option
val find_tftp_server_name : dhcp_option list -> string option
val find_time_offset : dhcp_option list -> int32 option
val find_trailer_encapsulation : dhcp_option list -> bool option
val find_user_class : dhcp_option list -> string option
val find_uuid_guid : dhcp_option list -> string option
val find_vendor_class_id : dhcp_option list -> string option
val find_vendor_specific : dhcp_option list -> string option
val collect_vi_vendor_class : dhcp_option list -> (int32 * string) list
val collect_vi_vendor_info : dhcp_option list -> (int32 * (int * string) list) list
val find_web_proxy_auto_disc : dhcp_option list -> string option
val find_private_classless_static_route : dhcp_option list -> string option
val find_other : int -> dhcp_option list -> (int * string) option
val collect_other : int -> dhcp_option list -> (int * string) list

(** {2 DHCP Packet - fixed-length fields, plus a variable-length list of options} *)

type pkt = {
  srcmac : Macaddr.t;
  dstmac : Macaddr.t;
  srcip : Ipaddr.V4.t;
  dstip : Ipaddr.V4.t;
  srcport : int;
  dstport : int;
  op : op;
  htype : htype;
  hlen : int;
  hops : int;
  xid : int32;
  secs : int;
  flags : flags;
  ciaddr : Ipaddr.V4.t;
  yiaddr : Ipaddr.V4.t;
  siaddr : Ipaddr.V4.t;
  giaddr : Ipaddr.V4.t;
  chaddr : Macaddr.t;
  sname : string;
  file : string;
  options : dhcp_option list;
}

(** Conversions for {! pkt}. *)

val pkt_of_buf : Cstruct.t -> int -> (pkt, [ `Msg of string | `Not_dhcp ]) result
val buf_of_pkt : pkt -> Cstruct.t
val pkt_into_buf : pkt -> Cstruct.t -> int

val pp_pkt : pkt Fmt.t

val client_id_of_pkt : pkt -> client_id

(** Helpers. *)

val is_dhcp : Cstruct.t -> int -> bool
(** [is_dhcp buf len] is true if [buf] is an Ethernet frame containing an IPv4
    header, UDP header, and DHCP packet. *)
