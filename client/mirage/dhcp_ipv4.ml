open Lwt.Infix

let src = Logs.Src.create "dhcp_client_mirage"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (Network : Mirage_net.S) = struct
  (* for now, just wrap a static ipv4 *)
  module DHCP = Dhcp_client_lwt.Make(Network)
  module Ethernet = Ethernet.Make(DHCP)
  module Arp = Arp.Make(Ethernet)
  include Static_ipv4.Make(Ethernet)(Arp)

  let connect ?(no_init = false) ?cidr ?gateway ?options ?requests net =
    ignore cidr; ignore gateway;
    DHCP.connect ?options ?requests net >>= fun dhcp ->
    DHCP.lease_stream dhcp
    |> Lwt_stream.filter_map (fun lease ->
        Option.map (fun config -> lease, config)
          (Dhcp_client_mirage.config_of_lease lease))
    |> Lwt_stream.last_new >>= fun (lease, (cidr, gateway)) ->
    Ethernet.connect dhcp >>= fun ethernet ->
    Arp.connect ethernet >>= fun arp ->
    connect ~no_init ~cidr ?gateway ethernet arp >|= fun t ->
    t, lease
end
