open Lwt.Infix

module Make (Network : Mirage_net.S) (E : Ethernet.S) (Arp : Arp.S) = struct
  (* for now, just wrap a static ipv4 *)
  module DHCP = Dhcp_client_mirage.Make(Network)
  include Static_ipv4.Make(E)(Arp)
  let connect ?cidr ?gateway net ethernet arp =
    (match cidr with
     | None ->
       DHCP.connect net >>= fun dhcp ->
       Lwt_stream.last_new dhcp
     | Some ip ->
       Lwt.return (ip, gateway)) >>= fun (cidr, gateway) ->
    connect ~cidr ?gateway ethernet arp
end
