let src = Logs.Src.create "dhcp_client_mirage"
module Log = (val Logs.src_log src : Logs.LOG)

let config_of_lease lease : Mirage_protocols_lwt.ipv4_config option =
  let open Dhcp_wire in
  (* ipv4_config expects a single IP address and the information
   * needed to construct a prefix.  It can optionally use one router. *)
  let address = lease.yiaddr in
  match Dhcp_wire.find_subnet_mask lease.options with
  | None ->
    Log.info (fun f -> f "Lease obtained with no subnet mask; discarding it");
    Log.debug (fun f -> f "Unusable lease: %s" @@ Dhcp_wire.pkt_to_string lease);
    None
  | Some subnet ->
    let network = Ipaddr.V4.Prefix.of_netmask subnet address in
    let valid_routers = Dhcp_wire.collect_routers lease.options in
    match valid_routers with
    | [] -> Some Mirage_protocols_lwt.{ address; network; gateway = None }
    | hd::_ ->
      Some Mirage_protocols_lwt.{ address; network; gateway = (Some hd) }

module Make(Time : Mirage_types_lwt.TIME) (Net : Mirage_types_lwt.NETWORK) = struct
  open Lwt.Infix
  open Mirage_protocols_lwt

  type t = ipv4_config Lwt_stream.t

  let connect ?(requests : Dhcp_wire.option_code list option) net =
    let module Lwt_client = Dhcp_client_lwt.Make(Time)(Net) in
    Lwt_client.connect ?requests net >>= fun lease_stream ->
    Lwt.return @@ Lwt_stream.filter_map config_of_lease lease_stream

end
