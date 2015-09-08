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

module Make (I : Dhcp_S.INTERFACE) : Dhcp_S.SERVER with type interface = I.t = struct
  module C = Config.Make (I)
  open C
  open Lwt
  open Dhcp

  type interface = I.t

  let make_reply config subnet reqpkt
      ~ciaddr ~yiaddr ~siaddr ~giaddr options =
    let op = Bootreply in
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
    let srcmac = I.mac subnet.interface in
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
        | _ -> invalid_arg ("Can't send message type " ^ (string_of_msgtype m))
    in
    let srcip = I.addr subnet.interface in
    { srcmac; dstmac; srcip; dstip; srcport; dstport;
      op; htype; hlen; hops; xid; secs; flags;
      ciaddr; yiaddr; siaddr; giaddr; chaddr; sname; file;
      options }

  let send_pkt pkt interface =
    I.send interface (buf_of_pkt pkt)

  let for_us pkt interface =
    (pkt.dstmac = I.mac interface ||
     pkt.dstmac = Macaddr.broadcast)
    &&
    (pkt.dstip = I.addr interface ||
     pkt.dstip = Ipaddr.V4.broadcast)

  let valid_pkt pkt =
    if pkt.op <> Bootrequest then
      false
    else if pkt.htype <> Ethernet_10mb then
      false
    else if pkt.hlen <> 6 then
      false
    else if pkt.hops <> 0 then
      false
    else
      true

  let input_decline_release config subnet pkt =
    let open Util in
    lwt msgtype = match msgtype_of_options pkt.options with
      | Some msgtype -> return (string_of_msgtype msgtype)
      | None -> Lwt.fail_with "Unexpected message type"
    in
    lwt () = Log.debug_lwt "%s packet received %s" msgtype
        (string_of_pkt pkt)
    in
    let ourip = I.addr subnet.interface in
    let reqip = request_ip_of_options pkt.options in
    let sidip = server_identifier_of_options pkt.options in
    let m = message_of_options pkt.options in
    let client_id = client_id_of_pkt pkt in
    match sidip with
    | None -> Log.warn_lwt "%s without server identifier, ignoring" msgtype
    | Some sidip ->
      if ourip <> sidip then
        return_unit                 (* not for us *)
      else
        match reqip with
        | None -> Log.warn_lwt "%s without request ip, ignoring" msgtype
        | Some reqip ->  (* check if the lease is actually his *)
          match Lease.lookup client_id pkt.srcmac subnet.lease_db with
          | None -> Log.warn_lwt "%s for unowned lease, ignoring" msgtype
          | Some _ -> Lease.remove client_id pkt.srcmac subnet.lease_db;
            let s = some_or_default m "unspecified" in
            Log.info_lwt "%s, client %s declined lease for %s, reason %s"
              msgtype
              (string_of_client_id client_id)
              (Ipaddr.V4.to_string reqip)
              s
  let input_decline = input_decline_release
  let input_release = input_decline_release

  let input_inform config subnet pkt =
    lwt () = Log.debug_lwt "INFORM packet received %s" (string_of_pkt pkt) in
    if pkt.ciaddr = Ipaddr.V4.unspecified then
      Lwt.fail_invalid_arg "DHCPINFORM with no ciaddr"
    else
      let ourip = I.addr subnet.interface in
      let options =
        let open Util in
        cons (Message_type DHCPACK) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (vendor_class_id_of_options pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (parameter_requests_of_options pkt.options) with
        | Some preqs ->
          options_from_parameter_requests preqs subnet.options
        | None -> []
      in
      let pkt = make_reply config subnet pkt
          ~ciaddr:pkt.ciaddr ~yiaddr:Ipaddr.V4.unspecified
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      Log.debug_lwt "REQUEST->NAK reply:\n%s" (string_of_pkt pkt) >>= fun () ->
      send_pkt pkt subnet.interface

  let input_request config subnet pkt =
    lwt () = Log.debug_lwt "REQUEST packet received %s" (string_of_pkt pkt) in
    let drop = return_unit in
    let lease_db = subnet.lease_db in
    let client_id = client_id_of_pkt pkt in
    let lease = Lease.lookup client_id pkt.srcmac lease_db in
    let ourip = I.addr subnet.interface in
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
      Log.debug_lwt "REQUEST->NAK reply:\n%s" (string_of_pkt pkt) >>= fun () ->
      send_pkt pkt subnet.interface
    in
    let ack ?(renew=false) lease =
      let open Util in
      let lease = if renew then Lease.extend lease else lease in
      let lease_time, t1, t2 =
        Lease.timeleft3 lease C.t1_time_ratio C.t2_time_ratio
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
        | Some preqs -> options_from_parameter_requests preqs subnet.options
        | None -> []
      in
      let reply = make_reply config subnet pkt
          ~ciaddr:pkt.ciaddr ~yiaddr:lease.Lease.addr
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      assert (lease.Lease.client_id = client_id);
      Lease.replace client_id pkt.srcmac lease lease_db;
      Log.debug_lwt "REQUEST->ACK reply:\n%s" (string_of_pkt reply) >>= fun () ->
      send_pkt reply subnet.interface
    in
    match sidip, reqip, lease with
    | Some sidip, Some reqip, _ -> (* DHCPREQUEST generated during SELECTING state *)
      if sidip <> ourip then (* is it for us ? *)
        drop
      else if pkt.ciaddr <> Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 *)
        lwt () = Log.warn_lwt "Bad DHCPREQUEST, ciaddr is not 0" in
        drop
      else if not (Lease.addr_in_range pkt.srcmac reqip lease_db) then
        nak ~msg:"Requested address is not in subnet range" ()
      else
        (match lease with
         | Some lease ->
           if Lease.expired lease && not (Lease.addr_available reqip lease_db) then
             nak ~msg:"Lease has expired and address is taken" ()
           else if lease.Lease.addr <> reqip then
             nak ~msg:"Requested address is incorrect" ()
           else
             ack lease
         | None ->
           if not (Lease.addr_available reqip lease_db) then
             nak ~msg:"Requested address is not available" ()
           else
             ack (Lease.make client_id reqip (C.default_lease_time config subnet)))
    | None, Some reqip, Some lease ->   (* DHCPREQUEST @ INIT-REBOOT state *)
      let expired = Lease.expired lease in
      if pkt.ciaddr <> Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 *)
        lwt () = Log.warn_lwt "Bad DHCPREQUEST, ciaddr is not 0" in
        drop
      else if expired && not (Lease.addr_available reqip lease_db) then
        nak ~msg:"Lease has expired and address is taken" ()
      (* TODO check if it's in the correct network when giaddr <> 0 *)
      else if pkt.giaddr = Ipaddr.V4.unspecified &&
              not (Lease.addr_in_range pkt.srcmac reqip lease_db) then
        nak ~msg:"Requested address is not in subnet range" ()
      else if lease.Lease.addr <> reqip then
        nak ~msg:"Requested address is incorrect" ()
      else
        ack lease
    | None, None, Some lease -> (* DHCPREQUEST @ RENEWING/REBINDING state *)
      let expired = Lease.expired lease in
      if pkt.ciaddr = Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 renewal *)
        lwt () = Log.warn_lwt "Bad DHCPREQUEST, ciaddr is 0" in
        drop
      else if expired && not (Lease.addr_available lease.Lease.addr lease_db) then
        nak ~msg:"Lease has expired and address is taken" ()
      else if lease.Lease.addr <> pkt.ciaddr then
        nak ~msg:"Requested address is incorrect" ()
      else
        ack ~renew:true lease
    | _ -> drop

  let input_discover config subnet pkt =
    Log.debug "DISCOVER packet received %s" (string_of_pkt pkt);
    (* RFC section 4.3.1 *)
    (* Figure out the ip address *)
    let lease_db = subnet.lease_db in
    let id = client_id_of_pkt pkt in
    let lease = Lease.lookup id pkt.srcmac lease_db in
    let ourip = I.addr subnet.interface in
    let expired = match lease with
      | Some lease -> Lease.expired lease
      | None -> false
    in
    let addr = match lease with
      (* Handle the case where we have a lease *)
      | Some lease ->
        if not expired then
          Some lease.Lease.addr
        (* If the lease expired, the address might not be available *)
        else if (Lease.addr_available lease.Lease.addr lease_db) then
          Some lease.Lease.addr
        else
          Lease.get_usable_addr id subnet.range lease_db
      (* Handle the case where we have no lease *)
      | None -> match (request_ip_of_options pkt.options) with
        | Some req_addr ->
          if (Lease.addr_in_range pkt.srcmac req_addr lease_db) &&
             (Lease.addr_available req_addr lease_db) then
            Some req_addr
          else
            Lease.get_usable_addr id subnet.range lease_db
        | None -> Lease.get_usable_addr id subnet.range lease_db
    in
    (* Figure out the lease lease_time *)
    let lease_time = match (ip_lease_time_of_options pkt.options) with
      | Some ip_lease_time ->
        if C.lease_time_good config subnet ip_lease_time then
          ip_lease_time
        else
          C.default_lease_time config subnet
      | None -> match lease with
        | None -> C.default_lease_time config subnet
        | Some lease -> if expired then
            C.default_lease_time config subnet
          else
            Lease.timeleft lease
    in
    match addr with
    | None -> Log.warn_lwt "No ips left to offer !"
    | Some addr ->
      let open Util in
      (* Start building the options *)
      let t1 = Int32.of_float
          (C.t1_time_ratio *. (Int32.to_float lease_time)) in
      let t2 = Int32.of_float
          (C.t2_time_ratio *. (Int32.to_float lease_time)) in
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
        | Some preqs -> options_from_parameter_requests preqs subnet.options
        | None -> []
      in
      let pkt = make_reply config subnet pkt
          ~ciaddr:Ipaddr.V4.unspecified ~yiaddr:addr
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      Log.debug_lwt "DISCOVER reply:\n%s" (string_of_pkt pkt) >>= fun () ->
      send_pkt pkt subnet.interface

  let input_pkt config subnet pkt =
    if not (for_us pkt subnet.interface) then
      return_unit
    else if valid_pkt pkt then
      (* Check if we have a subnet configured on the receiving interface *)
      match msgtype_of_options pkt.options with
      | Some DHCPDISCOVER -> input_discover config subnet pkt
      | Some DHCPREQUEST  -> input_request config subnet pkt
      | Some DHCPDECLINE  -> input_decline config subnet pkt
      | Some DHCPRELEASE  -> input_release config subnet pkt
      | Some DHCPINFORM   -> input_inform config subnet pkt
      | None -> Log.warn_lwt "Got malformed packet: no dhcp msgtype"
      | Some m -> Log.debug_lwt "Unhandled msgtype %s" (string_of_msgtype m)
    else
      Log.warn_lwt "Invalid packet %s" (string_of_pkt pkt)

  let rec dhcp_recv config subnet =
    lwt buffer = I.recv subnet.interface in
    let n = Cstruct.len buffer in
    Log.debug "dhcp sock read %d bytes on interface %s" n
      (I.name subnet.interface);
    (* Input the packet *)
    lwt () = match (pkt_of_buf buffer n) with
      | exception Dhcp.Not_dhcp s -> Log.debug_lwt "Packet isn't dhcp: %s" s
      | exception Invalid_argument e -> Log.warn_lwt "Bad packet: %s" e
      | pkt ->
        lwt () = Log.debug_lwt "valid packet from %d bytes" n in
        try_lwt
          input_pkt config subnet pkt
        with
          Invalid_argument e -> Log.warn_lwt "Input pkt %s" e
    in
    dhcp_recv config subnet

  exception Syntax_error of string

  let parse_choke lex s =
    let open Lexing in
    let pos = lex.lex_curr_p in
    let str = Printf.sprintf "%s at line %d around `%s`"
        s pos.pos_lnum (Lexing.lexeme lex)
    in
    raise (Syntax_error str)

  let parse_networks configtxt =
    let lex = Lexing.from_string configtxt in
    try
      let ast = Parser.main Lexer.lex lex in
      List.map (fun s -> s.Config.network) ast.Config.subnets
    with
    | Parser.Error -> parse_choke lex "Parser error"
    | Lexer.Error e -> raise (Syntax_error e)
    | Config.Ast_error e -> parse_choke lex e

  let parse_config configtxt interfaces =
    let lex = Lexing.from_string configtxt in
    try
      C.config_of_ast (Parser.main Lexer.lex lex) interfaces
    with
    | Parser.Error -> parse_choke lex "Parser error"
    | Lexer.Error e -> raise (Syntax_error e)
    | C.Error e -> parse_choke lex e
    | Config.Ast_error e -> parse_choke lex e

  let create configtxt verbosity interfaces =
    Log.current_level := Log.level_of_str verbosity;
    let config = parse_config configtxt interfaces in
    let threads = List.map (fun subnet ->
        dhcp_recv config subnet) config.subnets
    in
    pick threads
end
