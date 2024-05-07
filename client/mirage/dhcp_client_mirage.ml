let src = Logs.Src.create "dhcp_client_mirage"
module Log = (val Logs.src_log src : Logs.LOG)

let config_of_lease lease =
  let open Dhcp_wire in
  (* ipv4_config expects a single IP address and the information
     needed to construct a prefix.  It can optionally use one router. *)
  let address = lease.yiaddr in
  match Dhcp_wire.find_subnet_mask lease.options with
  | None ->
    Log.info (fun f -> f "Lease obtained with no subnet mask; discarding it");
    Log.debug (fun f -> f "Unusable lease: %s" @@ Dhcp_wire.pkt_to_string lease);
    None
  | Some subnet ->
    match Ipaddr.V4.Prefix.of_netmask ~netmask:subnet ~address with
    | Error `Msg msg ->
      Log.info (fun f -> f "Invalid address and netmask combination %s, discarding" msg);
      None
    | Ok network ->
      let valid_routers = Dhcp_wire.collect_routers lease.options in
      match valid_routers with
      | [] -> Some (network, None)
      | hd::_ -> Some (network, Some hd)

module Make(Random : Mirage_random.S)(Net : Mirage_net.S) = struct
  open Lwt.Infix

  type t = (Ipaddr.V4.Prefix.t * Ipaddr.V4.t option) Lwt_stream.t

  let connect ?(requests : Dhcp_wire.option_code list option) net =
    let module Lwt_client = Dhcp_client_lwt.Make(Random)(Net) in
    Lwt_client.connect ~renew:false ?requests net >>= fun lease_stream ->
    Lwt.return @@ Lwt_stream.filter_map config_of_lease lease_stream
end
