open Lwt.Infix

module type S = sig
  module Net : Mirage_net.S
  module Ethernet : Ethernet.S
  module Arp : Arp.S
  module Ipv4 : Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t and type prefix = Ipaddr.V4.Prefix.t

  type t

  val lease : t -> Dhcp_wire.dhcp_option list option Lwt.t
  val net : t -> Net.t
  val ethernet : t -> Ethernet.t
  val arp : t -> Arp.t
  val ipv4 : t -> Ipv4.t
end

module type With_lease = sig
  type t
  val lease : t -> Dhcp_wire.dhcp_option list option Lwt.t
end

let src = Logs.Src.create "dhcp_client_mirage"
module Log = (val Logs.src_log src : Logs.LOG)

let config_of_lease lease =
  let open Dhcp_wire in
  (* ipv4_config expects a single IP address and the information
     needed to construct a prefix.  It can optionally use one router. *)
  let address = lease.yiaddr in
  match Dhcp_wire.find_subnet_mask lease.options with
  | None ->
    Log.err (fun f -> f "Lease obtained with no subnet mask");
    Log.debug (fun f -> f "Unusable lease: %a" Dhcp_wire.pp_pkt lease);
    failwith "Missing subnet mask in lease"
  | Some subnet ->
    let network = Ipaddr.V4.Prefix.of_netmask_exn ~netmask:subnet ~address in
    let valid_routers = Dhcp_wire.collect_routers lease.options in
    match valid_routers with
    | [] -> (network, None)
    | hd::_ -> (network, Some hd)

module Make (Network : Mirage_net.S) = struct
  (* for now, just wrap a static ipv4 *)
  module Net = Dhcp_client_lwt.Make(Network)
  module Ethernet = Ethernet.Make(Net)
  module Arp = Arp.Make(Ethernet)
  module Ipv4 = Static_ipv4.Make(Ethernet)(Arp)

  type t =
    Dhcp_wire.dhcp_option list option Lwt.t * Net.t * Ethernet.t * Arp.t *
    Ipv4.t

  let connect ?(no_init = false) ?cidr ?gateway ?options ?requests net =
    let lease_opt, registry = Lwt.wait () in
    (match no_init, cidr with
    | false, None ->
       Option.iter (fun g ->
           Log.warn (fun m -> m "No CIDR provided, but a gateway %a, which will be ignored (requesting a DHCP lease)"
                        Ipaddr.V4.pp g)) gateway;
       let requests = match requests with
         | None -> Dhcp_wire.[ SUBNET_MASK; ROUTERS ]
         | Some s -> s
       in
      Net.connect ?options ~requests net >>= fun dhcp ->
      Lwt_mvar.take (Net.lease_mvar dhcp) >>= fun lease ->
      Lwt.wakeup_later registry (Some lease.options);
      let cidr, gateway = config_of_lease lease in
      Lwt.async (fun () -> 
          let rec read_lease () =
            Lwt_mvar.take (Net.lease_mvar dhcp) >>= fun lease ->
            let cidr', _gateway' = config_of_lease lease in
            (* TODO read up on renewal *)
            if Ipaddr.V4.Prefix.compare cidr cidr' = 0 then
              read_lease ()
            else
              failwith "DHCP server handed out a different lease"
          in
          read_lease ());
      Lwt.return (dhcp, (cidr, gateway))
     | true, None ->
       Net.connect_no_dhcp net >>= fun dhcp ->
       Lwt.wakeup_later registry None;
       Lwt.return (dhcp, (Ipaddr.V4.(Prefix.make 32 localhost), gateway))
     | _, Some cidr ->
       Net.connect_no_dhcp net >>= fun dhcp ->
       Lwt.wakeup_later registry None;
       Lwt.return (dhcp, (cidr, gateway))) >>= fun (dhcp, (cidr, gateway)) ->
    Ethernet.connect dhcp >>= fun ethernet ->
    Arp.connect ethernet >>= fun arp ->
    Ipv4.connect ~no_init ~cidr ?gateway ethernet arp >>= fun ip ->
    Lwt.return (lease_opt, dhcp, ethernet, arp, ip)

  let lease (lease, _, _, _, _) = lease
  let net (_, net, _, _, _) = net
  let ethernet (_, _, ethernet, _, _) = ethernet
  let arp (_, _, _, arp, _) = arp
  let ipv4 (_, _, _, _, ipv4) = ipv4
end

module Proj_net (T : S) = struct
  include T.Net
  let connect = T.net
end

module Proj_ethernet (T : S) = struct
  include T.Ethernet
  let connect = T.ethernet
end

module Proj_arp (T : S) = struct
  include T.Arp
  let connect = T.arp
end

module Proj_ipv4 (T : S) = struct
  include T.Ipv4
  let connect = T.ipv4
end
