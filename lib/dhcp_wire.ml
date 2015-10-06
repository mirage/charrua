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

let some_or_invalid f v = match f v with
  | Some x -> x
  | None -> invalid_arg ("Invalid value " ^ (string_of_int v))

cstruct dhcp {
  uint8_t      op;
  uint8_t      htype;
  uint8_t      hlen;
  uint8_t      hops;
  uint32_t     xid;
  uint16_t     secs;
  uint16_t     flags;
  uint32_t     ciaddr;
  uint32_t     yiaddr;
  uint32_t     siaddr;
  uint32_t     giaddr;
  uint8_t      chaddr[16];
  uint8_t      sname[64];
  uint8_t      file[128];
} as big_endian

cenum op {
  Bootrequest = 1;
  Bootreply   = 2;
} as uint8_t(sexp)

let int_to_op_exn v = some_or_invalid int_to_op v

cenum msgtype {
  DHCPDISCOVER = 1;
  DHCPOFFER;
  DHCPREQUEST;
  DHCPDECLINE;
  DHCPACK;
  DHCPNAK;
  DHCPRELEASE;
  DHCPINFORM;
} as uint8_t(sexp)

let int_to_msgtype_exn v = some_or_invalid int_to_msgtype v

cenum parameter_request {
  Pad = 0;
  Subnet_mask = 1;
  Time_offset = 2;
  Routers = 3;
  Time_servers = 4;
  Name_servers = 5;
  Dns_servers = 6;
  Log_servers = 7;
  Cookie_servers = 8;
  Lpr_servers = 9;
  Impress_servers = 10;
  Rsclocation_servers = 11;
  Hostname = 12;
  Bootfile_size = 13;
  Merit_dumpfile = 14;
  Domain_name = 15;
  Swap_server = 16;
  Root_path = 17;
  Extension_path = 18;
  Ipforwarding = 19;
  Nlsr = 20;
  Policy_filters = 21;
  Max_datagram = 22;
  Default_ip_ttl = 23;
  Pmtu_ageing_timo = 24;
  Pmtu_plateau_table = 25;
  Interface_mtu = 26;
  All_subnets_local = 27;
  Broadcast_addr = 28;
  Perform_mask_discovery = 29;
  Mask_supplier = 30;
  Perform_router_disc = 31;
  Router_sol_addr = 32;
  Static_routes = 33;
  Trailer_encapsulation = 34;
  Arp_cache_timo = 35;
  Ethernet_encapsulation = 36;
  Tcp_default_ttl = 37;
  Tcp_keepalive_interval = 38;
  Tcp_keepalive_garbage = 39;
  Nis_domain = 40;
  Nis_servers = 41;
  Ntp_servers = 42;
  Vendor_specific = 43;
  Netbios_name_servers = 44;
  Netbios_datagram_distrib_servers = 45;
  Netbios_node = 46;
  Netbios_scope = 47;
  Xwindow_font_servers = 48;
  Xwindow_display_managers = 49;
  Request_ip = 50;
  Ip_lease_time = 51;
  Option_overload = 52;
  Message_type = 53;
  Server_identifier = 54;
  Parameter_requests = 55;
  Message = 56;
  Max_message = 57;
  Renewal_t1 = 58;
  Rebinding_t2 = 59;
  Vendor_class_id = 60;
  Client_id = 61;
  Nis_plus_domain = 64;
  Nis_plus_servers = 65;
  Tftp_server_name = 66;
  Bootfile_name = 67;
  Mobile_ip_home_agent = 68;
  Smtp_servers = 69;
  Pop3_servers = 70;
  Nntp_servers = 71;
  Www_servers = 72;
  Finger_servers = 73;
  Irc_servers = 74;
  Streettalk_servers = 75;
  Streettalk_da = 76;
  User_class = 77;
  Directory_agent = 78;
  Service_scope = 79;
  Rapid_commit = 80;
  Client_fqdn = 81;
  Relay_agent_information = 82;
  Isns = 83;
  Unassigned_84 = 84;
  Nds_servers = 85;
  Nds_tree_name = 86;
  Nds_context = 87;
  Bcmcs_controller_domain_name_list = 88;
  Bcmcs_controller_ipv4_addr = 89;
  Authentication = 90;
  Client_last_transaction_time = 91;
  Associated_ip = 92;
  Client_system = 93;
  Client_ndi = 94;
  Ldap = 95;
  Unassigned_96 = 96;
  Uuid_guid = 97;
  User_auth = 98;
  Geoconf_civic = 99;
  Pcode = 100;
  Tcode = 101;
  Unassigned_102 = 102;
  Unassigned_103 = 103;
  Unassigned_104 = 104;
  Unassigned_105 = 105;
  Unassigned_106 = 106;
  Unassigned_107 = 107;
  Unassigned_108 = 108;
  Unassigned_109 = 109;
  Unassigned_110 = 110;
  Unassigned_111 = 111;
  Netinfo_address = 112;
  Netinfo_tag = 113;
  Url = 114;
  Unassigned_115 = 115;
  Auto_config = 116;
  Name_service_search = 117;
  Subnet_selection = 118;
  Domain_search = 119;
  Sip_servers = 120;
  Classes_static_route = 121;
  Ccc = 122;
  Geoconf = 123;
  Vi_vendor_class = 124;
  Vi_Vendor_info = 125;
  Unassigned_126 = 126;
  Unassigned_127 = 127;
  Pxe_128 = 128;
  Pxe_129 = 129;
  Pxe_130 = 130;
  Pxe_131 = 131;
  Pxe_132 = 132;
  Pxe_133 = 133;
  Pxe_134 = 134;
  Pxe_135 = 135;
  Pana_agent = 136;
  V4_lost = 137;
  Capwap_ac_v4 = 138;
  Ipv4_address_mos = 139;
  Ipv4_fqdn_mos = 140;
  Sip_ua_domains = 141;
  Ipv4_address_andsf = 142;
  Unassigned_143 = 143;
  Geolock = 144;
  Forcenew_nonce_capable = 145;
  Rdnss_selection = 146;
  Unassigned_147 = 147;
  Unassigned_148 = 148;
  Unassigned_149 = 149;
  Misc_150 = 150;
  Status_code = 151;
  Absolute_time = 152;
  Start_time_of_state = 153;
  Query_start_time = 154;
  Query_end_time = 155;
  Dhcp_state = 156;
  Data_source = 157;
  V4_pcp_server = 158;
  V4_portparams = 159;
  Dhcp_captive_portal = 160;
  Unassigned_161 = 161;
  Unassigned_162 = 162;
  Unassigned_163 = 163;
  Unassigned_164 = 164;
  Unassigned_165 = 165;
  Unassigned_166 = 166;
  Unassigned_167 = 167;
  Unassigned_168 = 168;
  Unassigned_169 = 169;
  Unassigned_170 = 170;
  Unassigned_171 = 171;
  Unassigned_172 = 172;
  Unassigned_173 = 173;
  Unassigned_174 = 174;
  Etherboot_175 = 175;
  Ip_telefone = 176;
  Etherboot_177 = 177;
  Unassigned_178 = 178;
  Unassigned_179 = 179;
  Unassigned_180 = 180;
  Unassigned_181 = 181;
  Unassigned_182 = 182;
  Unassigned_183 = 183;
  Unassigned_184 = 184;
  Unassigned_185 = 185;
  Unassigned_186 = 186;
  Unassigned_187 = 187;
  Unassigned_188 = 188;
  Unassigned_189 = 189;
  Unassigned_190 = 190;
  Unassigned_191 = 191;
  Unassigned_192 = 192;
  Unassigned_193 = 193;
  Unassigned_194 = 194;
  Unassigned_195 = 195;
  Unassigned_196 = 196;
  Unassigned_197 = 197;
  Unassigned_198 = 198;
  Unassigned_199 = 199;
  Unassigned_200 = 200;
  Unassigned_201 = 201;
  Unassigned_202 = 202;
  Unassigned_203 = 203;
  Unassigned_204 = 204;
  Unassigned_205 = 205;
  Unassigned_206 = 206;
  Unassigned_207 = 207;
  Pxe_linux = 208;
  Configuration_file = 209;
  Path_prefix = 210;
  Reboot_time = 211;
  Option_6rd = 212;
  V4_access_domain = 213;
  Unassigned_214 = 214;
  Unassigned_215 = 215;
  Unassigned_216 = 216;
  Unassigned_217 = 217;
  Unassigned_218 = 218;
  Unassigned_219 = 219;
  Subnet_allocation = 220;
  Virtual_subnet_selection = 221;
  Unassigned_222 = 222;
  Unassigned_223 = 223;
  Reserved_224 = 224;
  Reserved_225 = 225;
  Reserved_226 = 226;
  Reserved_227 = 227;
  Reserved_228 = 228;
  Reserved_229 = 229;
  Reserved_230 = 230;
  Reserved_231 = 231;
  Reserved_232 = 232;
  Reserved_233 = 233;
  Reserved_234 = 234;
  Reserved_235 = 235;
  Reserved_236 = 236;
  Reserved_237 = 237;
  Reserved_238 = 238;
  Reserved_239 = 239;
  Reserved_240 = 241;
  Reserved_242 = 242;
  Reserved_243 = 243;
  Reserved_244 = 244;
  Reserved_245 = 245;
  Reserved_246 = 246;
  Reserved_247 = 247;
  Reserved_248 = 248;
  Reserved_249 = 249;
  Reserved_250 = 250;
  Reserved_251 = 251;
  Web_proxy_auto_disc = 252;
  Reserved_253 = 253;
  Reserved_254 = 254;
  End = 255;
} as uint8_t(sexp)

let int_to_parameter_request_exn v = some_or_invalid int_to_parameter_request v
