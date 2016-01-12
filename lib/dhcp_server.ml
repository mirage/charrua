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

module Lease = struct

  open Sexplib.Conv
  open Sexplib.Std

  module Client_id = struct
    open Dhcp_wire

    type t = client_id

    let compare a b =
      match a, b with
      | Hwaddr maca,  Hwaddr macb -> Macaddr.compare maca macb
      | Id ida,  Id idb -> String.compare ida idb
      | Id _, Hwaddr _ -> -1
      | Hwaddr _, Id _ -> 1
  end

module Addr_map = Map.Make(Ipaddr.V4)
module Id_map = Map.Make(Client_id)

(* Lease (dhcp bindings) operations *)
type t = {
  tm_start   : int32;
  tm_end     : int32;
  addr       : Ipaddr.V4.t;
  client_id  : Dhcp_wire.client_id;
} with sexp

(* Database, collection of leases *)
type database = {
  id_map : t Id_map.t;
  addr_map : t Addr_map.t;
} (* with sexp *)

let update_db id_map addr_map =
  { id_map; addr_map }

let make_db () = update_db Id_map.empty Addr_map.empty

let make client_id addr ~duration ~now =
  let tm_start = Int32.of_float now in
  let tm_end = Int32.add tm_start duration in
  { tm_start; tm_end; addr; client_id }

(* XXX defaults fixed leases to one hour, policy does not belong here. *)
let make_fixed mac addr ~now =
  make (Dhcp_wire.Hwaddr mac) addr ~duration:(Int32.of_int (60 * 60)) ~now

let remove lease db =
  update_db
    (Id_map.remove lease.client_id db.id_map)
    (Addr_map.remove lease.addr db.addr_map)

let replace lease db =
  (* First clear both maps *)
  let clr_map = remove lease db in
  update_db
    (Id_map.add lease.client_id lease clr_map.id_map)
    (Addr_map.add lease.addr lease clr_map.addr_map)

let timeleft lease ~now =
  let left = (Int32.to_float lease.tm_end) -. now in
  if left < 0. then Int32.zero else (Int32.of_float left)

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

let garbage_collect db ~now =
  update_db
    (Id_map.filter (fun _ lease -> not (expired lease ~now)) db.id_map)
    (Addr_map.filter (fun _ lease -> not (expired lease ~now)) db.addr_map)

let lease_of_client_id client_id db = Util.find_some @@ fun () ->
  Id_map.find client_id db.id_map

let lease_of_addr addr db = Util.find_some @@ fun () ->
  Addr_map.find addr db.addr_map

let addr_allocated addr db =
  Util.true_if_some @@ lease_of_addr addr db

let addr_available addr db ~now =
  match lease_of_addr addr db with
  | None -> true
  | Some lease -> expired lease ~now

(*
 * We try to use the last 4 bytes of the mac address as a hint for the ip
 * address, if that fails, we try a linear search.
 *)
let get_usable_addr id db range ~now =
  let low_ip, high_ip = range in
  let low_32 = Ipaddr.V4.to_int32 low_ip in
  let high_32 = Ipaddr.V4.to_int32 high_ip in
  if (Int32.compare low_32 high_32) >= 0 then
    invalid_arg "invalid range, must be (low * high)";
  let hint_ip =
    let v = match id with
      | Dhcp_wire.Id s -> Int32.of_int 1805 (* XXX who cares *)
      | Dhcp_wire.Hwaddr hw ->
        let s = Bytes.sub (Macaddr.to_bytes hw) 2 4 in
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
  let rec linear_loop off f =
    let ip = Ipaddr.V4.of_int32 (Int32.add low_32 off) in
    if f ip then
      Some ip
    else if off = high_32 then
      None
    else
      linear_loop (Int32.succ off) f
  in
  if not (addr_allocated hint_ip db) then
    Some hint_ip
  else match linear_loop Int32.zero (fun a -> not (addr_allocated a db)) with
    | Some ip -> Some ip
    | None -> linear_loop Int32.zero (fun a -> addr_available a db ~now)

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

  let fixed_addr_of_mac mac subnet =
    Util.find_map
      (fun host -> match host.hw_addr with
         | Some hw_addr -> if hw_addr = mac then host.fixed_addr else None
         | None         -> None)
          subnet.hosts

  let find_lease client_id mac db subnet ~now =
    match (fixed_addr_of_mac mac subnet) with
    | Some fixed_addr -> Some (Lease.make_fixed mac fixed_addr ~now), true
    | None -> Lease.lease_of_client_id client_id db, false

  let good_address mac addr subnet db =
    match (fixed_addr_of_mac mac subnet) with
      (* If this is a fixed address, it's good if mac matches ip. *)
    | Some fixed_addr -> addr = fixed_addr
    | None -> Util.addr_in_range addr subnet.range

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
    let all_options = subnet.options @ config.options in
    let maybe_both fn fnr =
      match fn all_options with
      | [] -> None
      | l -> Some (fnr l)
    in
    let maybe_replace fn fnr =
      match fn all_options with
      | Some x -> Some (fnr x)
      | None -> None
    in
    Util.filter_map
      (function
        | ROUTERS ->
          maybe_both collect_routers (fun x -> Routers x)
        | DNS_SERVERS ->
          maybe_both collect_dns_servers (fun x -> Dns_servers x)
        | NTP_SERVERS ->
          maybe_both collect_ntp_servers (fun x -> Ntp_servers x)
        | DOMAIN_NAME ->
          maybe_replace find_domain_name (fun x -> Domain_name x)
        | _ -> None)
      preqs

  let input_decline_release config db subnet pkt now =
    let open Util in
    let msgtype = match find_message_type pkt.options with
      | Some msgtype -> msgtype_to_string msgtype
      | None -> failwith "Unexpected message type"
    in
    let ourip = subnet.ip_addr in
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
        | Some reqip ->  (* check if the lease is actually his *)
          let lease, fixed_lease = find_lease client_id pkt.chaddr db subnet ~now in
          match lease with
          | None -> Silence (* lease is unowned, ignore *)
          | Some lease ->
            Update (
              if not fixed_lease then
                Lease.remove lease db
              else
                db)

  let input_decline = input_decline_release
  let input_release = input_decline_release

  let input_inform (config : Config.t) db subnet pkt =
    if pkt.ciaddr = Ipaddr.V4.unspecified then
      bad_packet "DHCPINFORM without ciaddr"
    else
      let ourip = subnet.ip_addr in
      let options =
        let open Util in
        cons (Message_type DHCPACK) @@
        cons (Server_identifier ourip) @@
        cons_if_some_f (find_vendor_class_id pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (find_parameter_requests pkt.options) with
        | Some preqs -> collect_replies config subnet preqs
        | None -> []
      in
      let pkt = make_reply config subnet pkt
          ~ciaddr:pkt.ciaddr ~yiaddr:Ipaddr.V4.unspecified
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      Reply (pkt, db)

  let input_request config db subnet pkt now =
    let client_id = client_id_of_pkt pkt in
    let lease, fixed_lease = find_lease client_id pkt.chaddr db subnet ~now in
    let ourip = subnet.ip_addr in
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
      let pkt = make_reply config subnet pkt
          ~ciaddr:Ipaddr.V4.unspecified ~yiaddr:Ipaddr.V4.unspecified
          ~siaddr:Ipaddr.V4.unspecified ~giaddr:pkt.giaddr options
      in
      Reply (pkt, db)
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
        cons_if_some_f (find_vendor_class_id pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (find_parameter_requests pkt.options) with
        | Some preqs -> collect_replies config subnet preqs
        | None -> []
      in
      let reply = make_reply config subnet pkt
          ~ciaddr:pkt.ciaddr ~yiaddr:lease.Lease.addr
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      assert (lease.Lease.client_id = client_id);
      if not fixed_lease then
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
      else if not (good_address pkt.chaddr reqip subnet db) then
        nak ~msg:"Requested address is not in subnet range" ()
      else
        (match lease with
         | Some lease ->
           if Lease.expired lease now && not (Lease.addr_available reqip db ~now) then
             nak ~msg:"Lease has expired and address is taken" ()
           else if lease.Lease.addr <> reqip then
             nak ~msg:"Requested address is incorrect" ()
           else
             ack lease
         | None ->
           if not (Lease.addr_available reqip db ~now) then
             nak ~msg:"Requested address is not available" ()
           else
             ack (Lease.make client_id reqip
                    ~duration:(Config.default_lease_time config subnet) ~now))
    | None, Some reqip, Some lease ->   (* DHCPREQUEST @ INIT-REBOOT state *)
      if pkt.ciaddr <> Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 *)
        bad_packet "Bad DHCPREQUEST, ciaddr is not 0"
      else if Lease.expired lease ~now &&
              not (Lease.addr_available reqip db ~now) then
        nak ~msg:"Lease has expired and address is taken" ()
        (* TODO check if it's in the correct network when giaddr <> 0 *)
      else if pkt.giaddr = Ipaddr.V4.unspecified &&
              not (good_address pkt.chaddr reqip subnet db) then
        nak ~msg:"Requested address is not in subnet range" ()
      else if lease.Lease.addr <> reqip then
        nak ~msg:"Requested address is incorrect" ()
      else
        ack lease
    | None, None, Some lease -> (* DHCPREQUEST @ RENEWING/REBINDING state *)
      if pkt.ciaddr = Ipaddr.V4.unspecified then (* violates RFC2131 4.3.2 renewal *)
        bad_packet "Bad DHCPREQUEST, ciaddr is not 0"
      else if Lease.expired lease ~now &&
              not (Lease.addr_available lease.Lease.addr db ~now) then
        nak ~msg:"Lease has expired and address is taken" ()
      else if lease.Lease.addr <> pkt.ciaddr then
        nak ~msg:"Requested address is incorrect" ()
      else
        ack ~renew:true lease
    | _ -> Silence

  let discover_addr lease db subnet pkt now =
    let id = client_id_of_pkt pkt in
    match lease with
    (* Handle the case where we have a lease *)
    | Some lease ->
      if not (Lease.expired lease ~now) then
        Some lease.Lease.addr
        (* If the lease expired, the address might not be available *)
      else if (Lease.addr_available lease.Lease.addr db ~now) then
        Some lease.Lease.addr
      else
        Lease.get_usable_addr id db subnet.range ~now
    (* Handle the case where we have no lease *)
    | None -> match (find_request_ip pkt.options) with
      | Some req_addr ->
        if (good_address pkt.chaddr req_addr subnet db) &&
           (Lease.addr_available req_addr db ~now) then
          Some req_addr
        else
          Lease.get_usable_addr id db subnet.range ~now
      | None -> Lease.get_usable_addr id db subnet.range ~now

  let discover_lease_time config subnet lease db pkt now =
    match (find_ip_lease_time pkt.options) with
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

  let input_discover config db subnet pkt now =
    (* RFC section 4.3.1 *)
    (* Figure out the ip address *)
    let id = client_id_of_pkt pkt in
    let lease, fixed_lease = find_lease id pkt.chaddr db subnet ~now in
    let ourip = subnet.ip_addr in
    let addr = discover_addr lease db subnet pkt now in
    (* Figure out the lease lease_time *)
    let lease_time = discover_lease_time config subnet lease db pkt now in
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
        cons_if_some_f (find_vendor_class_id pkt.options)
          (fun vid -> Vendor_class_id vid) @@
        match (find_parameter_requests pkt.options) with
        | Some preqs -> collect_replies config subnet preqs
        | None -> []
      in
      let pkt = make_reply config subnet pkt
          ~ciaddr:Ipaddr.V4.unspecified ~yiaddr:addr
          ~siaddr:ourip ~giaddr:pkt.giaddr options
      in
      Reply (pkt, db)

  let input_pkt config db subnet pkt time =
    try
      if not (for_subnet pkt subnet) then
        Silence
      else if valid_pkt pkt then
        match find_message_type pkt.options with
        | Some DHCPDISCOVER -> input_discover config db subnet pkt time
        | Some DHCPREQUEST  -> input_request config db subnet pkt time
        | Some DHCPDECLINE  -> input_decline config db subnet pkt time
        | Some DHCPRELEASE  -> input_release config db subnet pkt time
        | Some DHCPINFORM   -> input_inform config db subnet pkt
        | None -> bad_packet "Malformed packet: no dhcp msgtype"
        | Some m -> Warning ("Unhandled msgtype " ^ (msgtype_to_string m))
      else
        bad_packet "Invalid packet"
    with
    | Invalid_argument e -> Error e
end
