open Lwt.Infix

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

module Registry : sig
  type 'a t
  val create : unit -> 'a t
  val register : 'a t -> 'a Lwt.t
  val notify : 'a t -> 'a -> unit
end = struct

  type 'a t = {
    mutable v : 'a option;
    mutable waiters : 'a Lwt.u list;
  }

  let create () =
    { v = None;
      waiters = [] }

  let register t =
    match t.v with
    | None ->
      let v, u = Lwt.wait () in
      t.waiters <- u :: t.waiters;
      v
    | Some v ->
      Lwt.return v

  let notify t v =
    (* XXX: if [t.v] is not [None] *)
    t.v <- Some v;
    List.iter (fun u -> Lwt.wakeup_later u v) t.waiters;
    (* We can "free" up the list now *)
    t.waiters <- []
end

module Make (Network : Mirage_net.S) = struct
  (* for now, just wrap a static ipv4 *)
  module DHCP = Dhcp_client_lwt.Make(Network)
  module Ethernet = Ethernet.Make(DHCP)
  module Arp = Arp.Make(Ethernet)
  include Static_ipv4.Make(Ethernet)(Arp)

  let connect ?registry ?(no_init = false) ?cidr ?gateway ?options ?requests net =
    (match no_init, cidr with
    | false, None ->
       Option.iter (fun g ->
           Log.warn (fun m -> m "No CIDR provided, but a gateway %a, which will be ignored (requesting a DHCP lease)"
                        Ipaddr.V4.pp g)) gateway;
       let requests = match requests with
         | None -> Dhcp_wire.[ SUBNET_MASK; ROUTERS ]
         | Some s -> s
       in
      DHCP.connect ?options ~requests net >>= fun dhcp ->
      Lwt_mvar.take (DHCP.lease_mvar dhcp) >>= fun lease ->
      Option.iter (fun r -> Registry.notify r (Some lease.options)) registry;
      let cidr, gateway = config_of_lease lease in
      Lwt.async (fun () -> 
          let rec read_lease () =
            Lwt_mvar.take (DHCP.lease_mvar dhcp) >>= fun lease ->
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
       DHCP.connect_no_dhcp net >>= fun dhcp ->
       Option.iter (fun r -> Registry.notify r None) registry;
       Lwt.return (dhcp, (Ipaddr.V4.(Prefix.make 32 localhost), gateway))
     | _, Some cidr ->
       DHCP.connect_no_dhcp net >>= fun dhcp ->
       Option.iter (fun r -> Registry.notify r None) registry;
       Lwt.return (dhcp, (cidr, gateway))) >>= fun (dhcp, (cidr, gateway)) ->
    Ethernet.connect dhcp >>= fun ethernet ->
    Arp.connect ethernet >>= fun arp ->
    connect ~no_init ~cidr ?gateway ethernet arp
end
