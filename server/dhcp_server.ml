(*
 * Copyright (c) 2015-2017 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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

module Config = struct
  type host = {
    hostname : string;
    options : Dhcp_wire.dhcp_option list;
    fixed_addr : Ipaddr.V4.t option;
    hw_addr : Macaddr.t;
  }

  type t = {
    options : Dhcp_wire.dhcp_option list;
    hostname : string;
    default_lease_time : int32;
    max_lease_time : int32;
    ip_addr : Ipaddr.V4.t;
    mac_addr : Macaddr.t;
    network : Ipaddr.V4.Prefix.t;
    range : (Ipaddr.V4.t * Ipaddr.V4.t) option;
    hosts : host list;
  }

  let t1_time_ratio = 0.5
  let t2_time_ratio = 0.8

  let lease_time_good config time = time <= config.max_lease_time

  let sanity_check config =
    (* Check if fixed addresses make sense *)
    List.iter (fun host ->
        match host.fixed_addr with
        | None -> ()
        | Some addr ->
          if not (Ipaddr.V4.Prefix.mem addr config.network) then
            invalid_arg (Printf.sprintf "Fixed address %s does not \
                                         belong to subnet %s"
                           (Ipaddr.V4.to_string addr)
                           (Ipaddr.V4.Prefix.to_string config.network))
          else match config.range with
               | None -> ()
               | Some range ->
                  if Util.addr_in_range addr range then
                    let low = fst range in
                    let high = snd range in
                    invalid_arg (Printf.sprintf "Fixed address %s must be \
                                                 outside of range %s:%s"
                                                (Ipaddr.V4.to_string addr)
                                                (Ipaddr.V4.to_string low)
                                                (Ipaddr.V4.to_string high)))
      config.hosts;
    config

  let make
      ?(hostname = "charrua-dhcp-server")
      ?(default_lease_time = 60 * 60 * 2) (* 2 hours *)
      ?(max_lease_time = 60 * 60 * 24)    (* 24 hours *)
      ?(hosts = [])
      ~addr_tuple
      ~network
      ~range
      ~options
      () =

    let open Dhcp_wire in
    (* Try to ensure the user doesn't pass bad options *)
    let () =
      List.iter (function
          | Subnet_mask _ | Renewal_t1 _ | Rebinding_t2 _ | Client_id _
          | Ip_lease_time _ | End | Pad | Request_ip _ | Parameter_requests _
          as option ->
            invalid_arg (Printf.sprintf "option %s is not allowed"
                           (dhcp_option_to_string option))
          | _ -> ())
        options
    in
    (* Prepend a Subnet_mask, since we can always infer that from the network,
       the user doesn't need to specify, it must always come first in case there
       is a Router option later on RFC2132 3.3 *)
    let options = Subnet_mask (Ipaddr.V4.Prefix.netmask network) :: options in
    let ip_addr = fst addr_tuple in
    let mac_addr = snd addr_tuple in
    sanity_check {
      options;
      hostname;
      default_lease_time = Int32.of_int default_lease_time;
      max_lease_time = Int32.of_int max_lease_time;
      ip_addr;
      mac_addr;
      network;
      range;
      hosts;
    }

  let config_of_ast addr_tuple (ast : Ast.t) =
    let ip_addr = fst addr_tuple in
    let mac_addr = snd addr_tuple in
    let subnets = ast.Ast.subnets in
    let subnet = List.find
        (fun s -> Ipaddr.V4.Prefix.mem ip_addr s.Ast.network)
        subnets
    in
    let hosts = List.map (fun h ->
          { hostname = h.Ast.hostname;
            options = h.Ast.options;
            fixed_addr = h.Ast.fixed_addr;
            hw_addr = h.Ast.hw_addr;
          }) subnet.Ast.hosts
    in
    let default_lease_time = Util.some_or_default
        subnet.Ast.default_lease_time ast.Ast.default_lease_time
    in
    let max_lease_time = Util.some_or_default
        subnet.Ast.max_lease_time ast.Ast.max_lease_time
    in
    let network = subnet.Ast.network in

    (* Prepend a Subnet_mask, since we can always infer that from the network,
       the user doesn't need to specify, it must always come first in case there
       is a Router option later on, RFC2132 3.3. subnet.Ast.options must come
       first, this way we make sure we hit the more specific option when
       searching for a single entry. *)
    let options = Dhcp_wire.Subnet_mask (Ipaddr.V4.Prefix.netmask network) ::
                  (subnet.Ast.options @ ast.Ast.options)
    in
    sanity_check {
      options;
      hostname = "charrua-dhcp-server"; (* XXX Implement server-name option. *)
      default_lease_time;
      max_lease_time;
      ip_addr;
      mac_addr;
      network = subnet.Ast.network;
      range = subnet.Ast.range;
      hosts = hosts;
    }

  let parse configtxt addr_tuple =
    let choke lex s =
      let open Lexing in
      let pos = lex.lex_curr_p in
      let str = Printf.sprintf "%s at line %d around `%s`"
          s pos.pos_lnum (Lexing.lexeme lex)
      in
      invalid_arg str
    in
    let lex = Lexing.from_string configtxt in
    let ast =
      try Dhcp_parser.main Dhcp_lexer.lex lex with
      | Dhcp_parser.Error -> choke lex "Parser Error"
      | Invalid_argument e -> choke lex e
    in
    config_of_ast addr_tuple ast

end

module Lease = struct
  module Client_id = struct
    open Dhcp_wire

    type t = client_id

    let compare a b =
      match a, b with
      | Hwaddr maca,  Hwaddr macb -> Macaddr.compare maca macb
      | Id (htype, ida),  Id (htype', idb) ->
        begin match compare htype htype' with
          | 0 -> String.compare ida idb
          | x -> x
        end
      | Id _, Hwaddr _ -> -1
      | Hwaddr _, Id _ -> 1
  end

  module Addr_map = Map.Make(Ipaddr.V4)
  module Lease_map = Map.Make(Client_id)

  (* Lease (dhcp bindings) operations *)
  type t = {
    tm_start   : int32;
    tm_end     : int32;
    addr       : Ipaddr.V4.t;
    client_id  : Dhcp_wire.client_id;
  }

  let to_string lease =
    "start " ^ Int32.to_string lease.tm_start ^
    " end " ^ Int32.to_string lease.tm_end ^
    " addr " ^ Ipaddr.V4.to_string lease.addr ^
    " client id " ^ Dhcp_wire.client_id_to_string lease.client_id

  (* Database, collection of leases *)
  type database = {
    lease_map : t Lease_map.t;
    addr_map : Client_id.t Addr_map.t;
  }

  let update_db lease_map addr_map =
    { lease_map; addr_map }

  let make_db () = update_db Lease_map.empty Addr_map.empty

  let db_to_list db = Lease_map.fold (fun _id lease l -> lease :: l) db.lease_map []

  let db_equal db1 db2 =
    (Lease_map.equal (fun l1 l2 -> l1 = l2) db1.lease_map db2.lease_map)
    &&
    (Addr_map.equal (fun a1 a2 -> a1 = a2) db1.addr_map db2.addr_map)

  let make client_id addr ~duration ~now =
    let tm_start = now in
    let tm_end = Int32.add tm_start duration in
    { tm_start; tm_end; addr; client_id }

  let make_fixed mac addr ~duration ~now =
    make (Dhcp_wire.Hwaddr mac) addr ~duration ~now

  let timeleft lease ~now =
    let left = Int32.sub lease.tm_end now in
    if left < Int32.zero then Int32.zero else left

  let timeleft_exn lease ~now =
    let left = timeleft lease ~now in
    if left = Int32.zero then invalid_arg "No time left for lease" else left

  let timeleft3 lease t1_ratio t2_ratio ~now =
    let left = Int32.to_float (timeleft lease ~now) in
    (Int32.of_float left,
     Int32.of_float (left *. t1_ratio),
     Int32.of_float (left *. t2_ratio))

  let extend lease ~now =
    let original = Int32.sub lease.tm_end lease.tm_start in
    make lease.client_id lease.addr ~duration:original ~now

  let expired lease ~now = timeleft lease ~now = Int32.zero

  let sanity_check db =
    assert (Addr_map.cardinal db.addr_map = Lease_map.cardinal db.lease_map);
    Lease_map.iter (fun client_id lease ->
        assert (client_id = (Addr_map.find lease.addr db.addr_map)))
      db.lease_map;
    Addr_map.iter (fun addr client_id ->
        let lease = Lease_map.find client_id db.lease_map in
        assert (lease.client_id = client_id);
        assert (lease.addr = addr))
      db.addr_map;
    db

  let garbage_collect db ~now =
    let lease_map = Lease_map.filter
        (fun _ lease -> not (expired lease ~now))
        db.lease_map
    in
    let addr_map = Addr_map.filter
        (fun _ client_id -> Lease_map.mem client_id lease_map)
        db.addr_map
    in
    update_db lease_map addr_map |> sanity_check

  let lease_of_client_id client_id db = Util.find_some @@ fun () ->
    Lease_map.find client_id db.lease_map

  let lease_of_addr addr db = Util.find_some @@ fun () ->
    Addr_map.find addr db.addr_map

  let remove lease db =
    update_db
      (Lease_map.remove lease.client_id db.lease_map)
      (Addr_map.remove lease.addr db.addr_map)

  let replace lease db =
    (* remove possible old one first *)
    let db =
      match Lease_map.find_opt lease.client_id db.lease_map with
      | None -> db
      | Some old_lease -> remove old_lease db
    in
    update_db
      (Lease_map.add lease.client_id lease db.lease_map)
      (Addr_map.add lease.addr lease.client_id db.addr_map)

  let lease_to_string l =
    Int32.to_string l.tm_start ^ "," ^ Int32.to_string l.tm_end ^ "," ^
    Ipaddr.V4.to_string l.addr ^ "," ^ Dhcp_wire.client_id_to_string l.client_id

  let lease_of_string s =
    match String.split_on_char ',' s with
    | tm_start :: tm_end :: addr :: client_id ->
      (match Int32.of_string_opt tm_start, Int32.of_string_opt tm_end, Ipaddr.V4.of_string addr, Dhcp_wire.string_to_client_id (String.concat "," client_id) with
       | Some tm_start, Some tm_end, Ok addr, Some client_id ->
         Some { tm_start ; tm_end ; addr ; client_id }
       | _ -> None)
    | _ -> None

  let db_to_string db =
    Lease_map.bindings db.lease_map |>
    List.map (fun (cid, lease) ->
        Dhcp_wire.client_id_to_string cid ^ ":" ^ lease_to_string lease
      ) |> String.concat "\n"

  let db_of_string s =
    let entries = String.split_on_char '\n' s in
    let things =
      List.fold_left (fun acc entry ->
          match acc with
          | None -> None
          | Some acc ->
            (match String.split_on_char ':' entry with
             | client_id :: lease ->
               (match Dhcp_wire.string_to_client_id client_id, lease_of_string (String.concat ":" lease) with
                | Some cid, Some lease ->
                  Some ((cid, lease) :: acc)
                | _ -> None)
             | _ -> None))
        (Some []) entries
    in
    match things with
    | Some l ->
      List.fold_left (fun db (cid, lease) ->
          assert (cid = lease.client_id);
          replace lease db) (make_db ()) l
    | None -> assert false

  let addr_allocated addr db =
    Util.true_if_some @@ lease_of_addr addr db

  let addr_free addr db = not (addr_allocated addr db)

(*
 * We try to use the last 4 bytes of the mac address as a hint for the ip
 * address, if that fails, we try a linear search.
 *)
  let get_usable_addr id db range =
    match range with
    | None -> None
    | Some range ->
    let low_ip, high_ip = range in
    let low_32 = Ipaddr.V4.to_int32 low_ip in
    let high_32 = Ipaddr.V4.to_int32 high_ip in
    if (Int32.compare low_32 high_32) > 0 then
      invalid_arg "invalid range, must be (low * high)";
    let hint_ip =
      let v = match id with
        | Dhcp_wire.Id (_, _s) -> Int32.of_int 1805 (* XXX who cares *)
        | Dhcp_wire.Hwaddr hw ->
          let s = String.sub (Macaddr.to_octets hw) 2 4 in
          let b0 = Int32.shift_left (Char.code s.[3] |> Int32.of_int) 0 in
          let b1 = Int32.shift_left (Char.code s.[2] |> Int32.of_int) 8 in
          let b2 = Int32.shift_left (Char.code s.[1] |> Int32.of_int) 16 in
          let b3 = Int32.shift_left (Char.code s.[0] |> Int32.of_int) 24 in
          Int32.zero |> Int32.logor b0 |> Int32.logor b1 |>
          Int32.logor b2 |> Int32.logor b3
      in
      Int32.rem v (Int32.sub (Int32.succ high_32) low_32) |>
      Int32.abs |>
      Int32.add low_32 |>
      Ipaddr.V4.of_int32
    in
    let rec linear_loop off =
      let ip = Ipaddr.V4.of_int32 (Int32.add low_32 off) in
      if addr_free ip db then
        Some ip
      else if off = high_32 then
        None
      else
        linear_loop (Int32.succ off)
    in
    if addr_free hint_ip db then
      Some hint_ip
    else
      linear_loop Int32.zero

end

module Input = struct
  open Config
  open Dhcp_wire

  let bad_packet fmt = Printf.ksprintf (fun s -> invalid_arg s) fmt

  type result =
    | Silence
    | Update of Lease.database
    | Reply of Dhcp_wire.pkt * Lease.database
    | Warning of string
    | Error of string

  let host_of_mac config mac = Util.find_some @@
    fun () -> List.find (fun host -> host.hw_addr = mac) config.hosts

  let fixed_addr_of_mac config mac =
    match host_of_mac config mac with
    | Some host -> host.fixed_addr
    | None -> None

  let _options_of_mac config mac =
    match host_of_mac config mac with
    | Some host -> host.options
    | None -> []

  let find_lease config client_id mac db ~now =
    match (fixed_addr_of_mac config mac) with
    | Some fixed_addr -> Some (Lease.make_fixed mac fixed_addr ~duration:config.default_lease_time ~now), true
    | None -> Lease.lease_of_client_id client_id db, false

  let good_address config mac addr _db =
    match (fixed_addr_of_mac config mac) with
      (* If this is a fixed address, it's good if mac matches ip. *)
    | Some fixed_addr -> addr = fixed_addr
    | None -> (match config.range with
      | None -> false
      | Some range -> Util.addr_in_range addr range)

  let make_reply config reqpkt
      ~ciaddr ~yiaddr ~siaddr ~giaddr options =
    let op = BOOTREPLY in
    let htype = Ethernet_10mb in
    let hlen = 6 in
    let hops = 0 in
    let xid = reqpkt.xid in
    let secs = 0 in
    let flags = reqpkt.flags in
    let chaddr = reqpkt.chaddr in
    let sname = config.hostname in
    let file = "" in
    (* Build the frame header *)
    let dstport = if giaddr = Ipaddr.V4.unspecified then
        client_port
      else
        server_port
    in
    let srcport = server_port in
    let srcmac = config.mac_addr in
    let dstmac, dstip = match (find_message_type options) with
      | None -> failwith "make_reply: No msgtype in options"
      | Some m -> match m with
        | DHCPNAK -> if giaddr <> Ipaddr.V4.unspecified then
            (reqpkt.srcmac, giaddr)
          else
            (Macaddr.broadcast, Ipaddr.V4.broadcast)
        | DHCPOFFER | DHCPACK ->
          if giaddr <> Ipaddr.V4.unspecified then
            (reqpkt.srcmac, giaddr)
          else if ciaddr <> Ipaddr.V4.unspecified then
            (reqpkt.srcmac, ciaddr)
          else if flags = Unicast then
            (reqpkt.srcmac, yiaddr)
          else
            (Macaddr.broadcast, Ipaddr.V4.broadcast)
        | _ -> invalid_arg ("Can't send message type " ^ msgtype_to_string m)
    in
    let srcip = config.ip_addr in
    { srcmac; dstmac; srcip; dstip; srcport; dstport;
      op; htype; hlen; hops; xid; secs; flags;
      ciaddr; yiaddr; siaddr; giaddr; chaddr; sname; file;
      options }

  let for_us config pkt =
    pkt.dstport = Dhcp_wire.server_port
    &&
    pkt.srcport = Dhcp_wire.client_port
    &&
    (pkt.dstmac = config.mac_addr ||
     pkt.dstmac = Macaddr.broadcast)
    &&
    (pkt.dstip = config.ip_addr ||
     pkt.dstip = Ipaddr.V4.broadcast)

  let valid_pkt pkt =
    if pkt.op <> BOOTREQUEST then
      false
    else if pkt.htype <> Ethernet_10mb then
      false
    else if pkt.hlen <> 6 then
      false
    else if pkt.hops <> 0 then
      false
    else
      true

  (* might be slow O(preqs * options) *)
  let replies_of_options options preqs =
    (* Sort parameter requests to guarantee ordering. *)
    let preqs =
      List.sort
        (fun a b -> compare (option_code_to_int a) (option_code_to_int b))
        preqs
    in
    let unassigned_options =
      List.filter (function Other (_ ,_) -> true | _ -> false)
        options
    in
    (* matches multiple options *)
    let m fn fnr =
      match fn options with
      | [] -> None
      | l -> Some (fnr l)
    in
    (* matches the first single option *)
    let s fn fnr =
      match fn options with
      | Some x -> Some (fnr x)
      | None -> None
    in
    let consider = function
      | SUBNET_MASK -> s find_subnet_mask (fun x -> Subnet_mask x)
      | TIME_OFFSET -> s find_time_offset (fun x -> Time_offset x)
      | ROUTERS -> m collect_routers (fun x -> Routers x)
      | DNS_SERVERS -> m collect_dns_servers (fun x -> Dns_servers x)
      | LOG_SERVERS -> m collect_log_servers (fun x -> Log_servers x)
      | LPR_SERVERS -> m collect_lpr_servers (fun x -> Lpr_servers x)
      | HOSTNAME -> s find_hostname (fun x -> Hostname x)
      | BOOTFILE_SIZE -> s find_bootfile_size (fun x -> Bootfile_size x)
      | DOMAIN_NAME -> s find_domain_name (fun x -> Domain_name x)
      | SWAP_SERVER -> s find_swap_server (fun x -> Swap_server x)
      | ROOT_PATH -> s find_root_path (fun x -> Root_path x)
      | EXTENSION_PATH -> s find_extension_path (fun x -> Extension_path x)
      | IPFORWARDING -> s find_ipforwarding (fun x -> Ipforwarding x)
      | NLSR -> s find_nlsr (fun x -> Nlsr x)
      | POLICY_FILTERS -> m collect_policy_filters (fun x -> Policy_filters x)
      | MAX_DATAGRAM -> s find_max_datagram (fun x -> Max_datagram x)
      | DEFAULT_IP_TTL -> s find_default_ip_ttl (fun x -> Default_ip_ttl x)
      | INTERFACE_MTU -> s find_interface_mtu (fun x -> Interface_mtu x)
      | ALL_SUBNETS_LOCAL -> s find_all_subnets_local (fun x -> All_subnets_local x)
      | BROADCAST_ADDR -> s find_broadcast_addr (fun x -> Broadcast_addr x)
      | PERFORM_ROUTER_DISC ->
        s find_perform_router_disc (fun x -> Perform_router_disc x)
      | ROUTER_SOL_ADDR -> s find_router_sol_addr (fun x -> Router_sol_addr x)
      | STATIC_ROUTES -> m collect_static_routes (fun x -> Static_routes x)
      | TRAILER_ENCAPSULATION ->
        s find_trailer_encapsulation (fun x -> Trailer_encapsulation x)
      | ARP_CACHE_TIMO -> s find_arp_cache_timo (fun x -> Arp_cache_timo x)
      | ETHERNET_ENCAPSULATION ->
        s find_ethernet_encapsulation (fun x -> Ethernet_encapsulation x)
      | TCP_DEFAULT_TTL -> s find_tcp_default_ttl (fun x -> Tcp_default_ttl x)
      | TCP_KEEPALIVE_INTERVAL ->
        s find_tcp_keepalive_interval (fun x -> Tcp_keepalive_interval x)
      | NIS_DOMAIN -> s find_nis_domain (fun x -> Nis_domain x)
      | NIS_SERVERS -> m collect_nis_servers (fun x -> Nis_servers x)
      | NTP_SERVERS -> m collect_ntp_servers (fun x -> Ntp_servers x)
      | VENDOR_SPECIFIC -> s find_vendor_specific (fun x -> Vendor_specific x)
      | NETBIOS_NAME_SERVERS ->
        m collect_netbios_name_servers (fun x -> Netbios_name_servers x)
      | NETBIOS_DATAGRAM_DISTRIB_SERVERS ->
        m collect_netbios_datagram_distrib_servers
          (fun x -> Netbios_datagram_distrib_servers x)
      | NETBIOS_NODE -> s find_netbios_node (fun x -> Netbios_node x)
      | NETBIOS_SCOPE -> s find_netbios_scope (fun x -> Netbios_scope x)
      | XWINDOW_FONT_SERVERS ->
        m collect_xwindow_font_servers (fun x -> Xwindow_font_servers x)
      | XWINDOW_DISPLAY_MANAGERS ->
        m collect_xwindow_display_managers (fun x -> Xwindow_display_managers x)
      | REQUEST_IP -> None (* Previously included *)
      | IP_LEASE_TIME -> None   (* Previously included *)
      | OPTION_OVERLOAD -> s find_option_overload (fun x -> Option_overload x)
      | MESSAGE_TYPE -> None (* Senseless *)
      | SERVER_IDENTIFIER -> None (* Previously included *)
      | PARAMETER_REQUESTS -> None (* Senseless *)
      | MESSAGE -> s find_message (fun x -> Message x)
      | MAX_MESSAGE -> s find_max_message (fun x -> Max_message x)
      | RENEWAL_T1 -> None (* Previously included *)
      | REBINDING_T2 -> None (* Previously included *)
      | VENDOR_CLASS_ID -> s find_vendor_class_id (fun x -> Vendor_class_id x)
      | CLIENT_ID -> None (* Senseless *)
      | NIS_PLUS_DOMAIN -> s find_nis_plus_domain (fun x -> Nis_plus_domain x)
      | NIS_PLUS_SERVERS ->
        m collect_nis_plus_servers (fun x -> Nis_plus_servers x)
      | TFTP_SERVER_NAME -> s find_tftp_server_name (fun x -> Tftp_server_name x)
      | BOOTFILE_NAME -> s find_bootfile_name (fun x -> Bootfile_name x)
      | MOBILE_IP_HOME_AGENT ->
        m collect_mobile_ip_home_agent (fun x -> Mobile_ip_home_agent x)
      | SMTP_SERVERS -> m collect_smtp_servers (fun x -> Smtp_servers x)
      | POP3_SERVERS -> m collect_pop3_servers (fun x -> Pop3_servers x)
      | NNTP_SERVERS -> m collect_nntp_servers (fun x -> Nntp_servers x)
      | IRC_SERVERS -> m collect_irc_servers (fun x -> Irc_servers x)
      | USER_CLASS -> s find_user_class (fun x -> User_class x)
      | RAPID_COMMIT -> s find_rapid_commit (fun _ -> Rapid_commit)
      | CLIENT_FQDN -> s find_client_fqdn (fun x -> Client_fqdn x)
      | RELAY_AGENT_INFORMATION ->
        s find_relay_agent_information (fun x -> Relay_agent_information x)
      | CLIENT_SYSTEM -> s find_client_system (fun x -> Client_system x)
      | CLIENT_NDI -> s find_client_ndi (fun x -> Client_ndi x)
      | UUID_GUID -> s find_uuid_guid (fun x -> Uuid_guid x)
      | PCODE -> s find_pcode (fun x -> Pcode x)
      | TCODE -> s find_tcode (fun x -> Tcode x)
      | IPV6ONLY -> s find_ipv6only (fun x -> IPv6_only x)
      | SUBNET_SELECTION -> s find_subnet_selection (fun x -> Subnet_selection x)
      | DOMAIN_SEARCH -> s find_domain_search (fun x -> Domain_search x)
      | SIP_SERVERS -> s find_sip_servers (fun x -> Sip_servers x)
      | CLASSLESS_STATIC_ROUTE ->
        s find_classless_static_route (fun x -> Classless_static_route x)
      | VI_VENDOR_INFO -> s find_vi_vendor_info (fun x -> Vi_vendor_info x)
      | MISC_150 -> s find_misc_150 (fun x -> Misc_150 x)
      | WEB_PROXY_AUTO_DISC ->
        s find_web_proxy_auto_disc (fun x -> Web_proxy_auto_disc x)
      | PRIVATE_CLASSLESS_STATIC_ROUTE ->
        s find_private_classless_static_route (fun x -> Private_classless_static_route x)
      | OTHER code ->
        find_option
          (function Other (c, _s) as u when c = code -> Some u | _ -> None)
          unassigned_options
      | PAD | END -> None       (* Senseless *)
    in
    Util.filter_map consider preqs

  let collect_replies config mac preqs =
    match host_of_mac config mac with
    | Some host -> replies_of_options (host.options @ config.options) preqs
    | None -> replies_of_options config.options preqs

  let collect_replies_test = collect_replies

  let input_decline config db pkt now =
    let msgtype = match find_message_type pkt.options with
      | Some msgtype -> msgtype_to_string msgtype
      | None -> failwith "Unexpected message type"
    in
    let ourip = config.ip_addr in
    let reqip = find_request_ip pkt.options in
    let sidip = find_server_identifier pkt.options in
    let client_id = client_id_of_pkt pkt in
    match sidip with
    | None -> bad_packet "%s without server identifier" msgtype
    | Some sidip ->
      if ourip <> sidip then
        Silence                 (* not for us *)
      else
        match reqip with
        | None -> bad_packet "%s without request ip" msgtype
        | Some _reqip ->  (* check if the lease is actually his *)
          let lease, fixed_lease =
            find_lease config client_id pkt.chaddr db ~now in
          match lease with
          | None -> Silence (* lease is unowned, ignore *)
          | Some lease ->
            Update (
              if not fixed_lease then
                Lease.remove lease db
              else
                db)

  let input_release config db pkt now =
    let msgtype = match find_message_type pkt.options with
      | Some msgtype -> msgtype_to_string msgtype
      | None -> failwith "Unexpected message type"
    in
    let ourip = config.ip_addr in
    let sidip = find_server_identifier pkt.options in
    let client_id = client_id_of_pkt pkt in
    match sidip with
    | None -> bad_packet "%s without server identifier" msgtype
    | Some sidip ->
      if ourip <> sidip then
        Silence                 (* not for us *)
      else
        let lease, fixed_lease =
          find_lease config client_id pkt.chaddr db ~now in
        match lease with
        | None -> Silence (* lease is unowned, ignore *)
        | Some lease ->
          Update
            (if not fixed_lease && pkt.ciaddr = lease.addr then
               Lease.remove lease db
             else
               db)

  let input_inform config db pkt =
    if pkt.ciaddr = Ipaddr.V4.unspecified then
      bad_packet "DHCPINFORM without ciaddr"
    else
      let ourip = config.ip_addr in
      let options =
        let open Util in
        cons (Message_type DHCPACK) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (find_vendor_class_id pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (find_parameter_requests pkt.options) with
        | Some preqs -> collect_replies config pkt.chaddr preqs
        | None -> []
      in
      let pkt = make_reply config pkt
          ~ciaddr:pkt.ciaddr ~yiaddr:Ipaddr.V4.unspecified
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      Reply (pkt, db)

  let input_request config db pkt now =
    let client_id = client_id_of_pkt pkt in
    let lease, fixed_lease = find_lease config client_id pkt.chaddr db ~now in
    let ourip = config.ip_addr in
    let reqip = find_request_ip pkt.options in
    let sidip = find_server_identifier pkt.options in
    let nak ?msg () =
      let open Util in
      let options =
        cons (Message_type DHCPNAK) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f msg (fun msg -> Message msg) @@
        cons_if_some_f (find_client_id pkt.options)
          (fun id -> Client_id id) @@
        cons_if_some_f (find_vendor_class_id pkt.options)
          (fun vid -> Vendor_class_id vid) []
      in
      let pkt = make_reply config pkt
          ~ciaddr:Ipaddr.V4.unspecified ~yiaddr:Ipaddr.V4.unspecified
          ~siaddr:Ipaddr.V4.unspecified ~giaddr:pkt.giaddr options
      in
      Reply (pkt, db)
    in
    let ack lease =
      let open Util in
      let lease = Lease.extend lease ~now in
      let lease_time, t1, t2 =
        Lease.timeleft3 lease Config.t1_time_ratio Config.t2_time_ratio ~now
      in
      let options =
        cons (Message_type DHCPACK) @@
        cons (Ip_lease_time lease_time) @@
        cons (Renewal_t1 t1) @@
        cons (Rebinding_t2 t2) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (find_vendor_class_id pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (find_parameter_requests pkt.options) with
        | Some preqs -> collect_replies config pkt.chaddr preqs
        | None -> []
      in
      let reply = make_reply config pkt
          ~ciaddr:pkt.ciaddr ~yiaddr:lease.Lease.addr
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      if not fixed_lease then
        let () = assert (lease.Lease.client_id = client_id) in
        Reply (reply, Lease.replace lease db)
      else
        Reply (reply, db)
    in
    match sidip, reqip, lease with
    | Some sidip, Some reqip, _ -> (* DHCPREQUEST generated during SELECTING state *)
      if sidip <> ourip then (* is it for us ? *)
        Silence
      else if pkt.ciaddr <> Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 *)
        Warning "Bad DHCPREQUEST, ciaddr is not 0"
      else if not (good_address config pkt.chaddr reqip db) then
        nak ~msg:"Requested address is not in subnet range" ()
      else
        (match lease with
         | Some lease ->
           if lease.Lease.addr <> reqip then
             nak ~msg:"Requested address is incorrect" ()
           else
             ack lease
         | None ->
           if (Lease.addr_allocated reqip db) then
             nak ~msg:"Requested address is allocated" ()
           else
             ack (Lease.make client_id reqip
                    ~duration:config.default_lease_time ~now))
    | None, Some reqip, Some lease ->   (* DHCPREQUEST @ INIT-REBOOT state *)
      if pkt.ciaddr <> Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 *)
        bad_packet "Bad DHCPREQUEST, ciaddr is not 0"
        (* TODO check if it's in the correct network when giaddr <> 0 *)
      else if pkt.giaddr = Ipaddr.V4.unspecified &&
              not (good_address config pkt.chaddr reqip db) then
        nak ~msg:"Requested address is not in subnet range" ()
      else if lease.Lease.addr <> reqip then
        nak ~msg:"Requested address is incorrect" ()
      else
        Silence
    | None, None, Some lease -> (* DHCPREQUEST @ RENEWING/REBINDING state *)
      if pkt.ciaddr = Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 renewal *)
        bad_packet "Bad DHCPREQUEST, ciaddr is not 0"
      else if lease.Lease.addr <> pkt.ciaddr then
        nak ~msg:"Requested address is incorrect" ()
      else
        ack lease
    | _ -> Silence

  let discover_addr config lease db pkt =
    let id = client_id_of_pkt pkt in
    match lease with
    (* Handle the case where we have a lease *)
    | Some lease -> Some lease.Lease.addr
    | None -> match (find_request_ip pkt.options) with
      | Some req_addr ->
        if (good_address config pkt.chaddr req_addr db) &&
           (Lease.addr_free req_addr db) then
          Some req_addr
        else
          Lease.get_usable_addr id db config.range
      | None -> Lease.get_usable_addr id db config.range

  let discover_lease_time config lease _db pkt now =
    match (find_ip_lease_time pkt.options) with
    | Some ip_lease_time ->
      if Config.lease_time_good config ip_lease_time then
        ip_lease_time
      else
        config.default_lease_time
    | None -> match lease with
      | None -> config.default_lease_time
      | Some lease -> if Lease.expired lease ~now then
          config.default_lease_time
        else
          Lease.timeleft lease ~now

  let input_discover config db pkt now =
    (* RFC section 4.3.1 *)
    (* Figure out the ip address *)
    let id = client_id_of_pkt pkt in
    let lease, _fixed_lease = find_lease config id pkt.chaddr db ~now in
    let ourip = config.ip_addr in
    let addr = discover_addr config lease db pkt in
    (* Figure out the lease lease_time *)
    let lease_time = discover_lease_time config lease db pkt now in
    match addr with
    | None -> Warning "No ips left to offer"
    | Some addr ->
      let open Util in
      (* Start building the options *)
      let t1 = Int32.of_float
          (Config.t1_time_ratio *. (Int32.to_float lease_time)) in
      let t2 = Int32.of_float
          (Config.t2_time_ratio *. (Int32.to_float lease_time)) in
      let options =
        cons (Message_type DHCPOFFER) @@
        cons (Ip_lease_time lease_time) @@
        cons (Renewal_t1 t1) @@
        cons (Rebinding_t2 t2) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (find_vendor_class_id pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (find_parameter_requests pkt.options) with
        | Some preqs ->
          collect_replies config pkt.chaddr preqs
        | None -> []
      in
      let pkt = make_reply config pkt
          ~ciaddr:Ipaddr.V4.unspecified ~yiaddr:addr
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      Reply (pkt, db)

  let input_pkt config db pkt time =
    try
      if not (for_us config pkt) then
        Silence
      else if valid_pkt pkt then
        match find_message_type pkt.options with
        | Some DHCPDISCOVER -> input_discover config db pkt time
        | Some DHCPREQUEST  -> input_request config db pkt time
        | Some DHCPDECLINE  -> input_decline config db pkt time
        | Some DHCPRELEASE  -> input_release config db pkt time
        | Some DHCPINFORM   -> input_inform config db pkt
        | None -> bad_packet "Malformed packet: no dhcp msgtype"
        | Some m -> Warning ("Unhandled msgtype " ^ msgtype_to_string m)
      else
        bad_packet "Invalid packet"
    with
    | Invalid_argument e -> Error e
end
