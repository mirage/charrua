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

(** {1 DHCP wire parsers} *)

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
val int_to_op_exn : int -> op
(** Raise exception [Invalid_argument] if [v < 0 || v > 255]  *)
val op_to_int : op -> int

val string_to_op : string -> op option
val op_to_string : op -> string

val sexp_of_op : op -> Sexplib.Sexp.t
val op_of_sexp : Sexplib.Sexp.t -> op

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
(** Raise exception [Invalid_argument] if not a valid {! msgtype} value *)

val string_to_msgtype : string -> msgtype option
val msgtype_to_string : msgtype -> string

val sexp_of_msgtype : msgtype -> Sexplib.Sexp.t
val msgtype_of_sexp : Sexplib.Sexp.t -> msgtype

(** {2 DHCP option codes} *)

type option_code =
  | PAD
  | SUBNET_MASK
  | TIME_OFFSET
  | ROUTERS
  | TIME_SERVERS
  | NAME_SERVERS
  | DNS_SERVERS
  | LOG_SERVERS
  | COOKIE_SERVERS
  | LPR_SERVERS
  | IMPRESS_SERVERS
  | RSCLOCATION_SERVERS
  | HOSTNAME
  | BOOTFILE_SIZE
  | MERIT_DUMPFILE
  | DOMAIN_NAME
  | SWAP_SERVER
  | ROOT_PATH
  | EXTENSION_PATH
  | IPFORWARDING
  | NLSR
  | POLICY_FILTERS
  | MAX_DATAGRAM
  | DEFAULT_IP_TTL
  | PMTU_AGEING_TIMO
  | PMTU_PLATEAU_TABLE
  | INTERFACE_MTU
  | ALL_SUBNETS_LOCAL
  | BROADCAST_ADDR
  | PERFORM_MASK_DISCOVERY
  | MASK_SUPPLIER
  | PERFORM_ROUTER_DISC
  | ROUTER_SOL_ADDR
  | STATIC_ROUTES
  | TRAILER_ENCAPSULATION
  | ARP_CACHE_TIMO
  | ETHERNET_ENCAPSULATION
  | TCP_DEFAULT_TTL
  | TCP_KEEPALIVE_INTERVAL
  | TCP_KEEPALIVE_GARBAGE
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
  | NETWARE_IP_DOMAIN
  | NETWARE_IP_OPTION
  | NIS_PLUS_DOMAIN
  | NIS_PLUS_SERVERS
  | TFTP_SERVER_NAME
  | BOOTFILE_NAME
  | MOBILE_IP_HOME_AGENT
  | SMTP_SERVERS
  | POP3_SERVERS
  | NNTP_SERVERS
  | WWW_SERVERS
  | FINGER_SERVERS
  | IRC_SERVERS
  | STREETTALK_SERVERS
  | STREETTALK_DA
  | USER_CLASS
  | DIRECTORY_AGENT
  | SERVICE_SCOPE
  | RAPID_COMMIT
  | CLIENT_FQDN
  | RELAY_AGENT_INFORMATION
  | ISNS
  | UNASSIGNED_84
  | NDS_SERVERS
  | NDS_TREE_NAME
  | NDS_CONTEXT
  | BCMCS_CONTROLLER_DOMAIN_NAME_LIST
  | BCMCS_CONTROLLER_IPV4_ADDR
  | AUTHENTICATION
  | CLIENT_LAST_TRANSACTION_TIME
  | ASSOCIATED_IP
  | CLIENT_SYSTEM
  | CLIENT_NDI
  | LDAP
  | UNASSIGNED_96
  | UUID_GUID
  | USER_AUTH
  | GEOCONF_CIVIC
  | PCODE
  | TCODE
  | UNASSIGNED_102
  | UNASSIGNED_103
  | UNASSIGNED_104
  | UNASSIGNED_105
  | UNASSIGNED_106
  | UNASSIGNED_107
  | UNASSIGNED_108
  | UNASSIGNED_109
  | UNASSIGNED_110
  | UNASSIGNED_111
  | NETINFO_ADDRESS
  | NETINFO_TAG
  | URL
  | UNASSIGNED_115
  | AUTO_CONFIG
  | NAME_SERVICE_SEARCH
  | SUBNET_SELECTION
  | DOMAIN_SEARCH
  | SIP_SERVERS
  | CLASSLESS_STATIC_ROUTE
  | CCC
  | GEOCONF
  | VI_VENDOR_CLASS
  | VI_VENDOR_INFO
  | UNASSIGNED_126
  | UNASSIGNED_127
  | PXE_128
  | PXE_129
  | PXE_130
  | PXE_131
  | PXE_132
  | PXE_133
  | PXE_134
  | PXE_135
  | PANA_AGENT
  | V4_LOST
  | CAPWAP_AC_V4
  | IPV4_ADDRESS_MOS
  | IPV4_FQDN_MOS
  | SIP_UA_DOMAINS
  | IPV4_ADDRESS_ANDSF
  | UNASSIGNED_143
  | GEOLOCK
  | FORCENEW_NONCE_CAPABLE
  | RDNSS_SELECTION
  | UNASSIGNED_147
  | UNASSIGNED_148
  | UNASSIGNED_149
  | MISC_150
  | STATUS_CODE
  | ABSOLUTE_TIME
  | START_TIME_OF_STATE
  | QUERY_START_TIME
  | QUERY_END_TIME
  | DHCP_STATE
  | DATA_SOURCE
  | V4_PCP_SERVER
  | V4_PORTPARAMS
  | DHCP_CAPTIVE_PORTAL
  | UNASSIGNED_161
  | UNASSIGNED_162
  | UNASSIGNED_163
  | UNASSIGNED_164
  | UNASSIGNED_165
  | UNASSIGNED_166
  | UNASSIGNED_167
  | UNASSIGNED_168
  | UNASSIGNED_169
  | UNASSIGNED_170
  | UNASSIGNED_171
  | UNASSIGNED_172
  | UNASSIGNED_173
  | UNASSIGNED_174
  | ETHERBOOT_175
  | IP_TELEFONE
  | ETHERBOOT_177
  | UNASSIGNED_178
  | UNASSIGNED_179
  | UNASSIGNED_180
  | UNASSIGNED_181
  | UNASSIGNED_182
  | UNASSIGNED_183
  | UNASSIGNED_184
  | UNASSIGNED_185
  | UNASSIGNED_186
  | UNASSIGNED_187
  | UNASSIGNED_188
  | UNASSIGNED_189
  | UNASSIGNED_190
  | UNASSIGNED_191
  | UNASSIGNED_192
  | UNASSIGNED_193
  | UNASSIGNED_194
  | UNASSIGNED_195
  | UNASSIGNED_196
  | UNASSIGNED_197
  | UNASSIGNED_198
  | UNASSIGNED_199
  | UNASSIGNED_200
  | UNASSIGNED_201
  | UNASSIGNED_202
  | UNASSIGNED_203
  | UNASSIGNED_204
  | UNASSIGNED_205
  | UNASSIGNED_206
  | UNASSIGNED_207
  | PXE_LINUX
  | CONFIGURATION_FILE
  | PATH_PREFIX
  | REBOOT_TIME
  | OPTION_6RD
  | V4_ACCESS_DOMAIN
  | UNASSIGNED_214
  | UNASSIGNED_215
  | UNASSIGNED_216
  | UNASSIGNED_217
  | UNASSIGNED_218
  | UNASSIGNED_219
  | SUBNET_ALLOCATION
  | VIRTUAL_SUBNET_SELECTION
  | UNASSIGNED_222
  | UNASSIGNED_223
  | RESERVED_224
  | RESERVED_225
  | RESERVED_226
  | RESERVED_227
  | RESERVED_228
  | RESERVED_229
  | RESERVED_230
  | RESERVED_231
  | RESERVED_232
  | RESERVED_233
  | RESERVED_234
  | RESERVED_235
  | RESERVED_236
  | RESERVED_237
  | RESERVED_238
  | RESERVED_239
  | RESERVED_240
  | RESERVED_241
  | RESERVED_242
  | RESERVED_243
  | RESERVED_244
  | RESERVED_245
  | RESERVED_246
  | RESERVED_247
  | RESERVED_248
  | RESERVED_249
  | RESERVED_250
  | RESERVED_251
  | WEB_PROXY_AUTO_DISC
  | RESERVED_253
  | RESERVED_254
  | END
(** The type of a dhcp option code, these are all the values according to
    {{:https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml}iana}
*) 

(** Conversions of DHCP {! option_code}s. *)

val int_to_option_code : int -> option_code option
val int_to_option_code_exn : int -> option_code
val option_code_to_int : option_code -> int

val sexp_of_option_code : option_code -> Sexplib.Sexp.t
val option_code_of_sexp : Sexplib.Sexp.t -> option_code

val string_to_option_code : string -> option_code option
val option_code_to_string : option_code -> string

(** {2 DHCP hardware type} *)

type htype =
  | Ethernet_10mb
  | Other

(** Conversions of {! htype}. *)

val htype_of_sexp : Sexplib.Sexp.t -> htype
val sexp_of_htype : htype -> Sexplib.Sexp.t

(** {2 DHCP header flags}. *)

type flags =
  | Broadcast
  | Unicast

(** Conversions of {! flags}. *)

val flags_of_sexp : Sexplib.Sexp.t -> flags
val sexp_of_flags : flags -> Sexplib.Sexp.t

(** {2 DHCP Client identifier}. *)

type client_id =
  | Hwaddr of Macaddr.t
  | Id of string
(** A client_id is usually a mac address from a {! dhcp_option},
    but it can also be an opaque string. See {! client_id_of_pkt}. *)

(** Conversions of {! client_id}. *)

val client_id_of_sexp : Sexplib.Sexp.t -> client_id
val sexp_of_client_id : client_id -> Sexplib.Sexp.t

val client_id_to_string : client_id -> string

(** {2 DHCP options} *)

type dhcp_option =
  | Subnet_mask of Ipaddr.V4.t
  | Time_offset of int32
  | Routers of Ipaddr.V4.t list
  | Time_servers of Ipaddr.V4.t list
  | Name_servers of Ipaddr.V4.t list
  | Dns_servers of Ipaddr.V4.t list
  | Log_servers of Ipaddr.V4.t list
  | Cookie_servers of Ipaddr.V4.t list
  | Lpr_servers of Ipaddr.V4.t list
  | Impress_servers of Ipaddr.V4.t list
  | Rsclocation_servers of Ipaddr.V4.t list
  | Hostname of string
  | Bootfile_size of int
  | Merit_dumpfile of string
  | Domain_name of string
  | Swap_server of Ipaddr.V4.t
  | Root_path of string
  | Extension_path of string
  | Ipforwarding of bool
  | Nlsr of bool
  | Policy_filters of Ipaddr.V4.Prefix.t list
  | Max_datagram of int
  | Default_ip_ttl of int
  | Pmtu_ageing_timo of int32
  | Pmtu_plateau_table of int list
  | Interface_mtu of int
  | All_subnets_local of bool
  | Broadcast_addr of Ipaddr.V4.t
  | Perform_mask_discovery of bool
  | Mask_supplier of bool
  | Perform_router_disc of bool
  | Router_sol_addr of Ipaddr.V4.t
  | Static_routes of (Ipaddr.V4.t * Ipaddr.V4.t) list
  | Trailer_encapsulation of bool
  | Arp_cache_timo of int32
  | Ethernet_encapsulation of bool
  | Tcp_default_ttl of int
  | Tcp_keepalive_interval of int32
  | Tcp_keepalive_garbage of int
  | Nis_domain of string
  | Nis_servers of Ipaddr.V4.t list
  | Ntp_servers of Ipaddr.V4.t list
  | Vendor_specific of string
  | Netbios_name_servers of Ipaddr.V4.t list
  | Netbios_datagram_distrib_servers of Ipaddr.V4.t list
  | Netbios_node of int
  | Netbios_scope of string
  | Xwindow_font_servers of Ipaddr.V4.t list
  | Xwindow_display_managers of Ipaddr.V4.t list
  | Request_ip of Ipaddr.V4.t
  | Ip_lease_time of int32
  | Option_overload of int
  | Message_type of msgtype
  | Server_identifier of Ipaddr.V4.t
  | Parameter_requests of option_code list
  | Message of string
  | Max_message of int
  | Renewal_t1 of int32
  | Rebinding_t2 of int32
  | Vendor_class_id of string
  | Client_id of client_id
  | Nis_plus_domain of string
  | Nis_plus_servers of Ipaddr.V4.t list
  | Tftp_server_name of string
  | Bootfile_name of string
  | Mobile_ip_home_agent of Ipaddr.V4.t list
  | Smtp_servers of Ipaddr.V4.t list
  | Pop3_servers of Ipaddr.V4.t list
  | Nntp_servers of Ipaddr.V4.t list
  | Www_servers of Ipaddr.V4.t list
  | Finger_servers of Ipaddr.V4.t list
  | Irc_servers of Ipaddr.V4.t list
  | Streettalk_servers of Ipaddr.V4.t list
  | Streettalk_da of Ipaddr.V4.t list
  | Domain_search of string
  | Web_proxy_auto_disc of string
  | Unknown
(** Not all options are currently implemented. *)

(** Conversions of {! dhcp_option}. *)

val buf_of_options : Cstruct.t -> dhcp_option list -> Cstruct.t
val options_of_buf : Cstruct.t -> int -> dhcp_option list

val find_option : ('a -> 'b option) -> 'a list -> 'b option
val collect_options : ('a -> 'b list option) -> 'a list -> 'b list option

val dhcp_option_of_sexp : Sexplib.Sexp.t -> dhcp_option
val sexp_of_dhcp_option : dhcp_option -> Sexplib.Sexp.t

(** {2 DHCP Packet } *)

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

val pkt_of_buf : Cstruct.t -> int -> [> `Error of string | `Ok of pkt ]
val buf_of_pkt : pkt -> Cstruct.t

val pkt_of_sexp : Sexplib.Sexp.t -> pkt
val sexp_of_pkt : pkt -> Sexplib.Sexp.t

val client_id_of_pkt : pkt -> client_id
val pkt_to_string : pkt -> string
