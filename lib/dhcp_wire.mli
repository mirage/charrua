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
(** @raise Invalid_argument if [v < 0 || v > 255]  *)
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
(** @raise Invalid_argument if not a valid {! msgtype} value *)

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
  | ASSOCIATED_IPS
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
  | Pad                                     (* code 0 *)
  | Subnet_mask of Ipaddr.V4.t              (* code 1 *)
  | Time_offset of int32                    (* code 2 *)
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
  | Pmtu_ageing_timo of int32               (* code 24 *)
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
  | Arp_cache_timo of int32                 (* code 35 *)
  | Ethernet_encapsulation of bool          (* code 36 *)
  | Tcp_default_ttl of int                  (* code 37 *)
  | Tcp_keepalive_interval of int32         (* code 38 *)
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
  | Netware_ip_domain of string             (* code 62 *)
  | Netware_ip_option of string             (* code 63 *)
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
  | User_class of string                    (* code 77 *)
  | Directory_agent of string               (* code 78 *)
  | Service_scope of string                 (* code 79 *)
  | Rapid_commit                            (* code 80 *)
  | Client_fqdn of string                   (* code 81 *)
  | Relay_agent_information of string       (* code 82 *)
  | Isns of string                          (* code 83 *)
  | Nds_servers of string                   (* code 85 *)
  | Nds_tree_name of string                 (* code 86 *)
  | Nds_context of string                   (* code 87 *)
  | Bcmcs_controller_domain_name_list of string (* code 88 *)
  | Bcmcs_controller_ipv4_addrs of Ipaddr.V4.t list (* code 89 *)
  | Authentication of string                (* code 90 *)
  | Client_last_transaction_time of int32   (* code 91 *)
  | Associated_ips of Ipaddr.V4.t list       (* code 92 *)
  | Client_system of string                 (* code 93 *)
  | Client_ndi of string                    (* code 94 *)
  | Ldap of string                          (* code 95 *)
  | Uuid_guid of string                     (* code 97 *)
  | User_auth of string                     (* code 98 *)
  | Geoconf_civic of string                 (* code 99 *)
  | Pcode of string                         (* code 100 *)
  | Tcode of string                         (* code 101 *)
  | Netinfo_address of string               (* code 112 *)
  | Netinfo_tag of string                   (* code 113 *)
  | Url of string                           (* code 114 *)
  | Auto_config of int                      (* code 116 *)
  | Name_service_search of string           (* code 117 *)
  | Subnet_selection of Ipaddr.V4.t         (* code 118 *)
  | Domain_search of string                 (* code 119 *)
  | Sip_servers of string                   (* code 120 *)
  | Classless_static_route of string        (* code 121 *) (* XXX current, use better type *)
  | Ccc of string                           (* code 122 *)
  | Geoconf of string                       (* code 123 *)
  | Vi_vendor_class of string               (* code 124 *)
  | Vi_vendor_info of string                (* code 125 *)
  | Pxe_128 of string                       (* code 128 *)
  | Pxe_129 of string                       (* code 129 *)
  | Pxe_130 of string                       (* code 130 *)
  | Pxe_131 of string                       (* code 131 *)
  | Pxe_132 of string                       (* code 132 *)
  | Pxe_133 of string                       (* code 133 *)
  | Pxe_134 of string                       (* code 134 *)
  | Pxe_135 of string                       (* code 135 *)
  | Pana_agent of string                    (* code 136 *)
  | V4_lost of string                       (* code 137 *)
  | Capwap_ac_v4 of string                  (* code 138 *)
  | Ipv4_address_mos of string              (* code 139 *)
  | Ipv4_fqdn_mos of string                 (* code 140 *)
  | Sip_ua_domains of string                (* code 141 *)
  | Ipv4_address_andsf of string            (* code 142 *)
  | Geolock of string                       (* code 144 *)
  | Forcenew_nonce_capable of string        (* code 145 *)
  | Rdnss_selection of string               (* code 146 *)
  | Misc_150 of string                      (* code 150 *)
  | Status_code of string                   (* code 151 *)
  | Absolute_time of int32                  (* code 152 *)
  | Start_time_of_state of int32            (* code 153 *)
  | Query_start_time of int32               (* code 154 *)
  | Query_end_time of int32                 (* code 155 *)
  | Dhcp_state of int                       (* code 156 *)
  | Data_source of int                      (* code 157 *)
  | V4_pcp_server of string                 (* code 158 *)
  | V4_portparams of string                 (* code 159 *)
  | Dhcp_captive_portal of string           (* code 160 *)
  | Etherboot_175 of string                 (* code 175 *)
  | Ip_telefone of string                   (* code 176 *)
  | Etherboot_177 of string                 (* code 177 *)
  | Pxe_linux of int32                      (* code 208 *)
  | Configuration_file of string            (* code 209 *)
  | Path_prefix of string                   (* code 210 *)
  | Reboot_time of int32                    (* code 211 *)
  | Option_6rd of string                    (* code 212 *)
  | V4_access_domain of string              (* code 213 *) (* XXX current, better parsing *)
  | Subnet_allocation of int                (* code 220 *)
  | Virtual_subnet_selection of string      (* code 221 *)
  | Web_proxy_auto_disc of string           (* code 252 *)
  | End                                     (* code 255 *)
  | Unassigned of option_code * string      (* code * string *)
  with sexp
(** Not all options are currently implemented. *)

(** Conversions of {! dhcp_option}. *)

val buf_of_options : Cstruct.t -> dhcp_option list -> Cstruct.t
val options_of_buf : Cstruct.t -> int -> dhcp_option list

val find_option : (dhcp_option -> 'b option) -> dhcp_option list -> 'b option
(** [find_option f l] finds the first option where [f] evaluates to [Some] value
    on list [l] *)

val collect_options : ('a -> 'b list option) -> 'a list -> 'b list
(** [collect_options f l] collects all options where [f] evaluates to [Some]
    value on list [l], this is useful for list options like [Routers], if
    multiple list options are found, the resulting list is flattened. *)

val dhcp_option_of_sexp : Sexplib.Sexp.t -> dhcp_option
val sexp_of_dhcp_option : dhcp_option -> Sexplib.Sexp.t

val collect_associated_ips : dhcp_option list -> Ipaddr.V4.t list
val collect_bcmcs_controller_ipv4_addrs : dhcp_option list -> Ipaddr.V4.t list
val collect_cookie_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_dns_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_finger_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_impress_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_irc_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_log_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_lpr_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_name_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_netbios_datagram_distrib_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_netbios_name_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_nis_plus_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_nis_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_ntp_servers : dhcp_option list -> Ipaddr.V4.t list
val find_parameter_requests : dhcp_option list -> option_code list option
val collect_policy_filters : dhcp_option list -> Ipaddr.V4.Prefix.t list
val collect_routers : dhcp_option list -> Ipaddr.V4.t list
val collect_rsc_location_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_static_routes : dhcp_option list -> (Ipaddr.V4.t * Ipaddr.V4.t) list
val collect_streettalk_da : dhcp_option list -> Ipaddr.V4.t list
val collect_streettalk_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_time_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_www_servers : dhcp_option list -> Ipaddr.V4.t list
val collect_xwindow_display_managers : dhcp_option list -> Ipaddr.V4.t list
val collect_xwindow_font_servers : dhcp_option list -> Ipaddr.V4.t list
val find_absolute_time : dhcp_option list -> int32 option
val find_all_subnets_local : dhcp_option list -> bool option
val find_arp_cache_timo : dhcp_option list -> int32 option
val find_authentication : dhcp_option list -> string option
val find_auto_config : dhcp_option list -> int option
val find_bcmcs_controller_domain_name : dhcp_option list -> string option
val find_bootfile_name : dhcp_option list -> string option
val find_bootfile_size : dhcp_option list -> int option
val find_broadcast_addr : dhcp_option list -> Ipaddr.V4.t option
val find_capwap_ac_v4 : dhcp_option list -> string option
val find_ccc : dhcp_option list -> string option
val find_classless_static_route : dhcp_option list -> string option
val find_client_fqdn : dhcp_option list -> string option
val find_client_id : dhcp_option list -> client_id option
val find_client_last_transaction_time : dhcp_option list -> int32 option
val find_client_ndi : dhcp_option list -> string option
val find_client_system : dhcp_option list -> string option
val find_configuration_file : dhcp_option list -> string option
val find_data_source : dhcp_option list -> int option
val find_default_ip_ttl : dhcp_option list -> int option
val find_dhcp_captive_portal : dhcp_option list -> string option
val find_dhcp_state : dhcp_option list -> int option
val find_directory_agent : dhcp_option list -> string option
val find_domain_name : dhcp_option list -> string option
val find_domain_search : dhcp_option list -> string option
val find_etherboot_175 : dhcp_option list -> string option
val find_etherboot_177 : dhcp_option list -> string option
val find_ethernet_encapsulation : dhcp_option list -> bool option
val find_extension_path : dhcp_option list -> string option
val find_forcenew_nonce_capable : dhcp_option list -> string option
val find_geoconf : dhcp_option list -> string option
val find_geoconf_civic : dhcp_option list -> string option
val find_geolock : dhcp_option list -> string option
val find_hostname : dhcp_option list -> string option
val find_interface_mtu : dhcp_option list -> int option
val find_ip_lease_time : dhcp_option list -> int32 option
val find_ip_telefone : dhcp_option list -> string option
val find_ipforwarding : dhcp_option list -> bool option
val find_ipv4_address_andsf : dhcp_option list -> string option
val find_ipv4_address_mos : dhcp_option list -> string option
val find_ipv4_fqdn_mos : dhcp_option list -> string option
val find_isns : dhcp_option list -> string option
val find_ldap : dhcp_option list -> string option
val find_mask_supplier : dhcp_option list -> bool option
val find_max_datagram : dhcp_option list -> int option
val find_max_message : dhcp_option list -> int option
val find_merit_dumpfile : dhcp_option list -> string option
val find_message : dhcp_option list -> string option
val find_message_type : dhcp_option list -> msgtype option
val find_misc_150 : dhcp_option list -> string option
val collect_mobile_ip_home_agent : dhcp_option list -> Ipaddr.V4.t list
val find_name_service_search : dhcp_option list -> string option
val find_nds_context : dhcp_option list -> string option
val find_nds_servers : dhcp_option list -> string option
val find_nds_tree_name : dhcp_option list -> string option
val find_netbios_node : dhcp_option list -> int option
val find_netbios_scope : dhcp_option list -> string option
val find_netinfo_address : dhcp_option list -> string option
val find_netinfo_tag : dhcp_option list -> string option
val find_netware_ip_domain : dhcp_option list -> string option
val find_netware_ip_option : dhcp_option list -> string option
val find_nis_domain : dhcp_option list -> string option
val find_nis_plus_domain : dhcp_option list -> string option
val find_nlsr : dhcp_option list -> bool option
val collect_nntp_servers : dhcp_option list -> Ipaddr.V4.t list
val find_option_6rd : dhcp_option list -> string option
val find_option_overload : dhcp_option list -> int option
val find_pana_agent : dhcp_option list -> string option
val find_path_prefix : dhcp_option list -> string option
val find_pcode : dhcp_option list -> string option
val find_perform_mask_discovery : dhcp_option list -> bool option
val find_perform_router_disc : dhcp_option list -> bool option
val find_pmtu_ageing_timo : dhcp_option list -> int32 option
val find_pmtu_plateau_table : dhcp_option list -> int list option
val collect_pop3_servers : dhcp_option list -> Ipaddr.V4.t list
val find_pxe_128 : dhcp_option list -> string option
val find_pxe_129 : dhcp_option list -> string option
val find_pxe_130 : dhcp_option list -> string option
val find_pxe_131 : dhcp_option list -> string option
val find_pxe_132 : dhcp_option list -> string option
val find_pxe_133 : dhcp_option list -> string option
val find_pxe_134 : dhcp_option list -> string option
val find_pxe_135 : dhcp_option list -> string option
val find_pxe_linux : dhcp_option list -> int32 option
val find_query_end_time : dhcp_option list -> int32 option
val find_query_start_time : dhcp_option list -> int32 option
val find_rapid_commit : dhcp_option list -> dhcp_option option
val find_rdnss_selection : dhcp_option list -> string option
val find_rebinding_t2 : dhcp_option list -> int32 option
val find_reboot_time : dhcp_option list -> int32 option
val find_relay_agent_information : dhcp_option list -> string option
val find_renewal_t1 : dhcp_option list -> int32 option
val find_request_ip : dhcp_option list -> Ipaddr.V4.t option
val find_root_path : dhcp_option list -> string option
val find_router_sol_addr : dhcp_option list -> Ipaddr.V4.t option
val find_server_identifier : dhcp_option list -> Ipaddr.V4.t option
val find_service_scope : dhcp_option list -> string option
val find_sip_servers : dhcp_option list -> string option
val find_sip_ua_domains : dhcp_option list -> string option
val collect_smtp_servers : dhcp_option list -> Ipaddr.V4.t list
val find_start_time_of_state : dhcp_option list -> int32 option
val find_status_code : dhcp_option list -> string option
val find_subnet_allocation : dhcp_option list -> int option
val find_subnet_mask : dhcp_option list -> Ipaddr.V4.t option
val find_subnet_selection : dhcp_option list -> Ipaddr.V4.t option
val find_swap_server : dhcp_option list -> Ipaddr.V4.t option
val find_tcode : dhcp_option list -> string option
val find_tcp_default_ttl : dhcp_option list -> int option
val find_tcp_keepalive_garbage : dhcp_option list -> int option
val find_tcp_keepalive_interval : dhcp_option list -> int32 option
val find_tftp_server_name : dhcp_option list -> string option
val find_time_offset : dhcp_option list -> int32 option
val find_trailer_encapsulation : dhcp_option list -> bool option
val find_url : dhcp_option list -> string option
val find_user_auth : dhcp_option list -> string option
val find_user_class : dhcp_option list -> string option
val find_uuid_guid : dhcp_option list -> string option
val find_v4_access_domain : dhcp_option list -> string option
val find_v4_lost : dhcp_option list -> string option
val find_v4_pcp_server : dhcp_option list -> string option
val find_v4_portparams : dhcp_option list -> string option
val find_vendor_class_id : dhcp_option list -> string option
val find_vendor_specific : dhcp_option list -> string option
val find_vi_vendor_class : dhcp_option list -> string option
val find_vi_vendor_info : dhcp_option list -> string option
val find_virtual_subnet_selection : dhcp_option list -> string option
val find_web_proxy_auto_disc : dhcp_option list -> string option

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

(** Helpers. *)

val is_dhcp : Cstruct.t -> int -> bool
(** [is_dhcp buf len] is true if [buf] is a DHCP packet. *)
