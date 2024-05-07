open Lwt.Infix

module Make(R : Mirage_random.S) (C : Mirage_clock.MCLOCK) (Network : Mirage_net.S) (E : Ethernet.S) (Arp : Arp.S) = struct
  (* for now, just wrap a static ipv4 *)
  module DHCP = Dhcp_client_mirage.Make(R)(Network)
  include Static_ipv4.Make(R)(C)(E)(Arp)
  let connect net ethernet arp =
    DHCP.connect net >>= fun dhcp ->
    Lwt_stream.last_new dhcp >>= fun (cidr, gateway) ->
    connect ~cidr ?gateway ethernet arp
end
