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

module Config = struct
  open Sexplib.Conv
  open Sexplib.Std

  type host = {
    hostname : string;
    options : Dhcp_wire.dhcp_option list;
    fixed_addr : Ipaddr.V4.t option;
    hw_addr : Macaddr.t option;
  } with sexp

  type subnet = {
    ip_addr : Ipaddr.V4.t;
    mac_addr : Macaddr.t;
    network : Ipaddr.V4.Prefix.t;
    range : Ipaddr.V4.t * Ipaddr.V4.t;
    options : Dhcp_wire.dhcp_option list;
    hosts : host list;
    default_lease_time : int32 option;
    max_lease_time : int32 option;
  } with sexp

  type t = {
    addresses : (Ipaddr.V4.t * Macaddr.t) list;
    subnets : subnet list;
    options : Dhcp_wire.dhcp_option list;
    hostname : string;
    default_lease_time : int32;
    max_lease_time : int32;
  } with sexp

  let config_of_ast (ast : Ast.t) addresses =
    let subnet_of_subnet_ast (s : Ast.subnet) =
      let ip_addr, mac_addr = try List.find (function
          | ipaddr, _ -> Ipaddr.V4.Prefix.mem ipaddr s.Ast.network) addresses
        with Not_found ->
          invalid_arg ("No address found for network " ^
                       (Ipaddr.V4.Prefix.to_string s.Ast.network))
      in
      let () = List.iter (fun (host : Ast.host) ->
          match host.Ast.fixed_addr with
          | None -> ()
          | Some addr ->
            if not (Ipaddr.V4.Prefix.mem addr s.Ast.network) then
              invalid_arg (Printf.sprintf "Fixed address %s does not \
                                           belong to subnet %s"
                             (Ipaddr.V4.to_string addr)
                             (Ipaddr.V4.Prefix.to_string s.Ast.network))
            else if Util.addr_in_range addr s.Ast.range then
              match s.Ast.range with
              | low, high ->
                invalid_arg (Printf.sprintf "Fixed address %s must be \
                                             outside of range %s:%s"
                               (Ipaddr.V4.to_string addr)
                               (Ipaddr.V4.to_string low)
                               (Ipaddr.V4.to_string high)))
          s.Ast.hosts
      in
      let hosts = List.map (fun h ->
          { hostname = h.Ast.hostname;
            options = h.Ast.options;
            fixed_addr = h.Ast.fixed_addr;
            hw_addr = h.Ast.hw_addr;
          }) s.Ast.hosts
      in
      { ip_addr;
        mac_addr;
        network = s.Ast.network;
        range = s.Ast.range;
        options = s.Ast.options;
        hosts;
        default_lease_time = s.Ast.default_lease_time;
        max_lease_time = s.Ast.max_lease_time }
    in
    let subnets = List.map subnet_of_subnet_ast ast.Ast.subnets in
    { addresses; subnets;
      options = ast.Ast.options;
      hostname = "Charrua DHCP Server"; (* XXX Implement server-name option. *)
      default_lease_time = ast.Ast.default_lease_time;
      max_lease_time = ast.Ast.max_lease_time }

  let fixed_addrs hosts =
    List.fold_left
      (fun alist host -> match (host.fixed_addr, host.hw_addr) with
         | Some fixed_addr, Some hw_addr -> (hw_addr, fixed_addr) :: alist
         | _ -> alist)
      [] hosts

  let parse configtxt addresses =
    let choke lex s =
      let open Lexing in
      let pos = lex.lex_curr_p in
      let str = Printf.sprintf "%s at ZZZZ line %d around `%s`"
          s pos.pos_lnum (Lexing.lexeme lex)
      in
      invalid_arg str
    in
    let lex = Lexing.from_string configtxt in
    let ast =
      try Parser.main Lexer.lex lex with
      | Parser.Error -> choke lex "Parser Error"
      | Invalid_argument e -> choke lex e
    in
    config_of_ast ast addresses

  let t1_time_ratio = 0.5
  let t2_time_ratio = 0.8

  let default_lease_time (config : t) (subnet : subnet) =
    match subnet.default_lease_time with
    | Some time -> time
    | None -> config.default_lease_time

  let lease_time_good (config : t) (subnet : subnet) time =
    let max_lease_time = match subnet.max_lease_time with
      | Some time -> time
      | None -> config.max_lease_time
    in
    time <= max_lease_time

end


module Input = struct
  open Config
  open Dhcp_wire

  let bad_packet fmt = Printf.ksprintf (fun s -> invalid_arg s) fmt

  type result =
    | Silence
    | Reply of Dhcp_wire.pkt
    | Warning of string
    | Error of string

  (* Find Option helpers *)
  let msgtype_of_options options =
    find_option (function Message_type m -> Some m | _ -> None) options
  let client_id_of_options options =
    find_option (function Client_id id -> Some id | _ -> None) options
  let request_ip_of_options options =
    find_option (function Request_ip ip -> Some ip | _ -> None) options
  let ip_lease_time_of_options options =
    find_option (function Ip_lease_time ip -> Some ip | _ -> None) options
  let server_identifier_of_options options =
    find_option (function Server_identifier sid -> Some sid | _ -> None) options
  let vendor_class_id_of_options options =
    find_option (function Vendor_class_id vid -> Some vid | _ -> None) options
  let message_of_options options =
    find_option (function Message m -> Some m | _ -> None) options
  let domain_name_of_options options =
    find_option (function Domain_name dn -> Some dn | _ -> None) options
  let parameter_requests_of_options options =
    collect_options (function Parameter_requests x -> Some x | _ -> None) options
  let routers_of_options options =
    collect_options (function Routers x -> Some x | _ -> None) options
  let dns_servers_of_options options =
    collect_options (function Dns_servers x -> Some x | _ -> None) options
  let ntp_servers_of_options options =
    collect_options (function Ntp_servers x -> Some x | _ -> None) options

  let make_reply config subnet reqpkt
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
    let srcmac = subnet.mac_addr in
    let dstmac, dstip = match (msgtype_of_options options) with
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
        | _ -> invalid_arg ("Can't send message type " ^ (msgtype_to_string m))
    in
    let srcip = subnet.ip_addr in
    { srcmac; dstmac; srcip; dstip; srcport; dstport;
      op; htype; hlen; hops; xid; secs; flags;
      ciaddr; yiaddr; siaddr; giaddr; chaddr; sname; file;
      options }

  let for_subnet pkt subnet =
    pkt.dstport = Dhcp_wire.server_port
    &&
    pkt.srcport = Dhcp_wire.client_port
    &&
    (pkt.dstmac = subnet.mac_addr ||
     pkt.dstmac = Macaddr.broadcast)
    &&
    (pkt.dstip = subnet.ip_addr ||
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
  let collect_replies (config : Config.t) (subnet : Config.subnet)
      (preqs : option_code list) =
    let maybe_both fn fnr =
      let scan options = match fn options with Some x -> x | None -> [] in
      match (scan subnet.options @ scan config.options) with
      | [] -> None
      | l -> Some (fnr l)
    in
    let maybe_replace fn fnr =
      match fn subnet.options with
      | Some x -> Some (fnr x)
      | None -> match fn config.options with
        | Some x -> Some (fnr x)
        | None -> None
    in
    Util.filter_map
      (function
        | ROUTERS ->
          maybe_both routers_of_options (fun x -> Routers x)
        | DNS_SERVERS ->
          maybe_both dns_servers_of_options (fun x -> Dns_servers x)
        | NTP_SERVERS ->
          maybe_both ntp_servers_of_options (fun x -> Ntp_servers x)
        | DOMAIN_NAME ->
          maybe_replace domain_name_of_options (fun x -> Domain_name x)
        | _ -> None)
      preqs

  let input_decline_release config lease_db subnet pkt now =
    let open Util in
    let msgtype = match msgtype_of_options pkt.options with
      | Some msgtype -> msgtype_to_string msgtype
      | None -> failwith "Unexpected message type"
    in
    let ourip = subnet.ip_addr in
    let reqip = request_ip_of_options pkt.options in
    let sidip = server_identifier_of_options pkt.options in
    let m = message_of_options pkt.options in
    let client_id = client_id_of_pkt pkt in
    match sidip with
    | None -> bad_packet "%s without server identifier" msgtype
    | Some sidip ->
      if ourip <> sidip then
        Silence                 (* not for us *)
      else
        match reqip with
        | None -> bad_packet "%s without request ip" msgtype
        | Some reqip ->  (* check if the lease is actually his *)
          match Lease.lookup client_id pkt.chaddr lease_db ~now with
          | None -> Silence (* lease is unowned, ignore *)
          | Some _ -> Lease.remove client_id pkt.chaddr lease_db;
            Warning (Printf.sprintf "%s, client %s declined lease for %s, reason %s"
                       (some_or_default m "unspecified")
                       msgtype
                       (client_id_to_string client_id)
                       (Ipaddr.V4.to_string reqip))
  let input_decline = input_decline_release
  let input_release = input_decline_release

  let input_inform (config : Config.t) subnet pkt =
    if pkt.ciaddr = Ipaddr.V4.unspecified then
      bad_packet "DHCPINFORM without ciaddr"
    else
      let ourip = subnet.ip_addr in
      let options =
        let open Util in
        cons (Message_type DHCPACK) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (vendor_class_id_of_options pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (parameter_requests_of_options pkt.options) with
        | Some preqs -> collect_replies config subnet preqs
        | None -> []
      in
      let pkt = make_reply config subnet pkt
          ~ciaddr:pkt.ciaddr ~yiaddr:Ipaddr.V4.unspecified
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      Reply pkt

  let input_request config lease_db subnet pkt now =
    let client_id = client_id_of_pkt pkt in
    let lease = Lease.lookup client_id pkt.chaddr lease_db ~now in
    let ourip = subnet.ip_addr in
    let reqip = request_ip_of_options pkt.options in
    let sidip = server_identifier_of_options pkt.options in
    let nak ?msg () =
      let open Util in
      let options =
        cons (Message_type DHCPNAK) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f msg (fun msg -> Message msg) @@
        cons_if_some_f (client_id_of_options pkt.options)
          (fun id -> Client_id id) @@
        cons_if_some_f (vendor_class_id_of_options pkt.options)
          (fun vid -> Vendor_class_id vid) []
      in
      let pkt = make_reply config subnet pkt
          ~ciaddr:Ipaddr.V4.unspecified ~yiaddr:Ipaddr.V4.unspecified
          ~siaddr:Ipaddr.V4.unspecified ~giaddr:pkt.giaddr options
      in
      Reply pkt
    in
    let ack ?(renew=false) lease =
      let open Util in
      let lease = if renew then Lease.extend lease ~now else lease in
      let lease_time, t1, t2 =
        Lease.timeleft3 lease Config.t1_time_ratio Config.t2_time_ratio ~now
      in
      let options =
        cons (Message_type DHCPACK) @@
        cons (Subnet_mask (Ipaddr.V4.Prefix.netmask subnet.network)) @@
        cons (Ip_lease_time lease_time) @@
        cons (Renewal_t1 t1) @@
        cons (Rebinding_t2 t2) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (vendor_class_id_of_options pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (parameter_requests_of_options pkt.options) with
        | Some preqs -> collect_replies config subnet preqs
        | None -> []
      in
      let reply = make_reply config subnet pkt
          ~ciaddr:pkt.ciaddr ~yiaddr:lease.Lease.addr
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      assert (lease.Lease.client_id = client_id);
      Lease.replace client_id pkt.chaddr lease lease_db;
      Reply reply
    in
    match sidip, reqip, lease with
    | Some sidip, Some reqip, _ -> (* DHCPREQUEST generated during SELECTING state *)
      if sidip <> ourip then (* is it for us ? *)
        Silence
      else if pkt.ciaddr <> Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 *)
        Warning "Bad DHCPREQUEST, ciaddr is not 0"
      else if not (Lease.addr_in_range pkt.chaddr reqip lease_db) then
        nak ~msg:"Requested address is not in subnet range" ()
      else
        (match lease with
         | Some lease ->
           if Lease.expired lease now && not (Lease.addr_available reqip lease_db ~now) then
             nak ~msg:"Lease has expired and address is taken" ()
           else if lease.Lease.addr <> reqip then
             nak ~msg:"Requested address is incorrect" ()
           else
             ack lease
         | None ->
           if not (Lease.addr_available reqip lease_db ~now) then
             nak ~msg:"Requested address is not available" ()
           else
             ack (Lease.make client_id reqip
                    ~duration:(Config.default_lease_time config subnet) ~now))
    | None, Some reqip, Some lease ->   (* DHCPREQUEST @ INIT-REBOOT state *)
      if pkt.ciaddr <> Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 *)
        bad_packet "Bad DHCPREQUEST, ciaddr is not 0"
      else if Lease.expired lease ~now &&
              not (Lease.addr_available reqip lease_db ~now) then
        nak ~msg:"Lease has expired and address is taken" ()
        (* TODO check if it's in the correct network when giaddr <> 0 *)
      else if pkt.giaddr = Ipaddr.V4.unspecified &&
              not (Lease.addr_in_range pkt.chaddr reqip lease_db) then
        nak ~msg:"Requested address is not in subnet range" ()
      else if lease.Lease.addr <> reqip then
        nak ~msg:"Requested address is incorrect" ()
      else
        ack lease
    | None, None, Some lease -> (* DHCPREQUEST @ RENEWING/REBINDING state *)
      if pkt.ciaddr = Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 renewal *)
        bad_packet "Bad DHCPREQUEST, ciaddr is not 0"
      else if Lease.expired lease ~now &&
              not (Lease.addr_available lease.Lease.addr lease_db ~now) then
        nak ~msg:"Lease has expired and address is taken" ()
      else if lease.Lease.addr <> pkt.ciaddr then
        nak ~msg:"Requested address is incorrect" ()
      else
        ack ~renew:true lease
    | _ -> Silence

  let discover_addr lease lease_db pkt now =
    let id = client_id_of_pkt pkt in
    match lease with
    (* Handle the case where we have a lease *)
    | Some lease ->
      if not (Lease.expired lease ~now) then
        Some lease.Lease.addr
        (* If the lease expired, the address might not be available *)
      else if (Lease.addr_available lease.Lease.addr lease_db ~now) then
        Some lease.Lease.addr
      else
        Lease.get_usable_addr id lease_db ~now
    (* Handle the case where we have no lease *)
    | None -> match (request_ip_of_options pkt.options) with
      | Some req_addr ->
        if (Lease.addr_in_range pkt.chaddr req_addr lease_db) &&
           (Lease.addr_available req_addr lease_db ~now) then
          Some req_addr
        else
          Lease.get_usable_addr id lease_db ~now
      | None -> Lease.get_usable_addr id lease_db ~now

  let discover_lease_time config subnet lease lease_db pkt now =
    match (ip_lease_time_of_options pkt.options) with
    | Some ip_lease_time ->
      if Config.lease_time_good config subnet ip_lease_time then
        ip_lease_time
      else
        Config.default_lease_time config subnet
    | None -> match lease with
      | None -> Config.default_lease_time config subnet
      | Some lease -> if Lease.expired lease ~now then
          Config.default_lease_time config subnet
        else
          Lease.timeleft lease ~now

  let input_discover config lease_db subnet pkt now =
    (* RFC section 4.3.1 *)
    (* Figure out the ip address *)
    let id = client_id_of_pkt pkt in
    let lease = Lease.lookup id pkt.chaddr lease_db ~now in
    let ourip = subnet.ip_addr in
    let addr = discover_addr lease lease_db pkt now in
    (* Figure out the lease lease_time *)
    let lease_time = discover_lease_time config subnet lease lease_db pkt now in
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
        cons (Subnet_mask (Ipaddr.V4.Prefix.netmask subnet.network)) @@
        cons (Ip_lease_time lease_time) @@
        cons (Renewal_t1 t1) @@
        cons (Rebinding_t2 t2) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (vendor_class_id_of_options pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (parameter_requests_of_options pkt.options) with
        | Some preqs -> collect_replies config subnet preqs
        | None -> []
      in
      let pkt = make_reply config subnet pkt
          ~ciaddr:Ipaddr.V4.unspecified ~yiaddr:addr
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      Reply pkt

  let input_pkt config lease_db subnet pkt time =
    try
      if not (for_subnet pkt subnet) then
        Silence
      else if valid_pkt pkt then
        match msgtype_of_options pkt.options with
        | Some DHCPDISCOVER -> input_discover config lease_db subnet pkt time
        | Some DHCPREQUEST  -> input_request config lease_db subnet pkt time
        | Some DHCPDECLINE  -> input_decline config lease_db subnet pkt time
        | Some DHCPRELEASE  -> input_release config lease_db subnet pkt time
        | Some DHCPINFORM   -> input_inform config subnet pkt
        | None -> bad_packet "Malformed packet: no dhcp msgtype"
        | Some m -> Warning ("Unhandled msgtype " ^ (msgtype_to_string m))
      else
        bad_packet "Invalid packet"
    with
    | Invalid_argument e -> Error e
end
