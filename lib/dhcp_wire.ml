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
  Domain_search_format = 119;
  Web_proxy_auto_disc = 252;
} as uint8_t(sexp)

let int_to_parameter_request_exn v = some_or_invalid int_to_parameter_request v
