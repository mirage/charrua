open Lwt.Infix

module Make(Dhcp_client : Mirage_protocols.DHCP_CLIENT) (R : Mirage_random.S) (C : Mirage_clock.MCLOCK) (E : Mirage_protocols.ETHERNET) (Arp : Mirage_protocols.ARP) = struct
  (* for now, just wrap a static ipv4 *)
  include Static_ipv4.Make(R)(C)(E)(Arp)
  let connect dhcp ethernet arp =
    Lwt_stream.last_new dhcp >>= fun (config : Mirage_protocols.ipv4_config) ->
    connect ~cidr:config.network ?gateway:config.gateway ethernet arp
end
