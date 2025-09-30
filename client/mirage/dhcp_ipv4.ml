open Lwt.Infix

let src = Logs.Src.create "dhcp_client_mirage"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (Network : Mirage_net.S) (E : Ethernet.S) (Arp : Arp.S) = struct
  (* for now, just wrap a static ipv4 *)
  module DHCP = Dhcp_client_mirage.Make(Network)
  include Static_ipv4.Make(E)(Arp)
  let connect ?(no_init = false) ?cidr ?gateway ?options ?requests net ethernet arp =
    (match cidr, no_init with
     | None, false ->
       Option.iter (fun g ->
           Log.warn (fun m -> m "No CIDR provided, but a gateway %a, which will be ignored (requesting a DHCP lease)"
                        Ipaddr.V4.pp g)) gateway;
       let requests = match requests with
         | None -> Dhcp_wire.[ SUBNET_MASK; ROUTERS ]
         | Some s -> s
       in
       DHCP.connect ?options ~requests net >>= fun dhcp ->
       Lwt_stream.last_new dhcp
     | None, true ->
       Lwt.return (Ipaddr.V4.(Prefix.make 32 localhost), gateway)
     | Some ip, _ ->
       Lwt.return (ip, gateway)) >>= fun (cidr, gateway) ->
    connect ~no_init ~cidr ?gateway ethernet arp
end
