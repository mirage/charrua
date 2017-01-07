let ipv4_config_of_lease lease : Mirage_types_lwt.ipv4_config option =
  let open Dhcp_wire in
  (* ipv4_config expects a single IP address and the information
   * needed to construct a prefix.  It can optionally use one router. *)
  let address = lease.yiaddr in
  match Dhcp_wire.find_subnet_mask lease.options with
  | None -> None
  | Some subnet ->
    let network = Ipaddr.V4.Prefix.of_netmask subnet address in
    let valid_routers = Dhcp_wire.collect_routers lease.options in
    match valid_routers with
    | [] -> Some (Mirage_types_lwt.{ address; network; gateway = None })
    | hd::_ -> Some (Mirage_types_lwt.{ address; network; gateway = (Some hd) })

let src = Logs.Src.create "dhcp_client"
module Log = (val Logs.src_log src : Logs.LOG)

module Make(Time : Mirage_types_lwt.TIME) (Net : Mirage_types_lwt.NETWORK) = struct
  open Lwt.Infix

  type t = Mirage_types_lwt.ipv4_config Lwt_stream.t

  let usable_config_of_lease = function
  | None -> None
  | Some lease -> ipv4_config_of_lease lease

  let connect ?(requests : Dhcp_wire.option_code list option) net =
    (* listener needs to occasionally check to see whether the state has advanced,
     * and if not, start a new attempt at a lease transaction *)
    let sleep_interval = Duration.of_sec 5 in

    let (client, dhcpdiscover) = Dhcp_client.create ?requests (Net.mac net) in
    let c = ref client in

    let rec repeater dhcpdiscover =
      Log.debug (fun f -> f "Sending DHCPDISCOVER...");
      Net.write net dhcpdiscover >|= Rresult.R.get_ok >>= fun () ->
      Time.sleep_ns sleep_interval >>= fun () ->
      match usable_config_of_lease (Dhcp_client.lease !c) with
      | Some lease ->
        Log.info (fun f -> f "Lease obtained! IP %a network %a gateway %a"
          Ipaddr.V4.pp_hum lease.address Ipaddr.V4.Prefix.pp_hum lease.network
          (Fmt.option Ipaddr.V4.pp_hum) lease.gateway);
          Lwt.return (Some lease)
      | None ->
        let (client, dhcpdiscover) = Dhcp_client.create ?requests (Net.mac net) in
        c := client;
        Log.info (fun f -> f "Timeout expired without a usable lease!  Starting over...");
        Log.debug (fun f -> f "New lease attempt: %a" Dhcp_client.pp !c);
        repeater dhcpdiscover 
    in
    let listen () =
      Net.listen net (fun buf ->
        match Dhcp_client.input !c buf with
        | (s, Some action) -> Net.write net action >|=
          Rresult.R.get_ok >>= fun () ->
          Log.debug (fun f -> f "State advanced! Now %a" Dhcp_client.pp s);
          c := s; Lwt.return_unit
        | (s, None) ->
          Log.debug (fun f -> f "No action! State is %a" Dhcp_client.pp s);
          c := s; Lwt.return_unit
      ) >|= Rresult.R.get_ok
    in
    let get_lease () =
      Lwt.pick [ (listen () >>= fun () -> Lwt.return None);
               repeater dhcpdiscover; ]
    in
    let s = Lwt_stream.from get_lease in
    Lwt.return s

end
