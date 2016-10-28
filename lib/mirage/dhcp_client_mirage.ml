let ipv4_config_of_lease lease : V1_LWT.ipv4_config option =
  let open Dhcp_wire in
  (* ipv4_config expects a single IP address and the information
   * needed to construct a prefix.  It can optionally use one router. *)
  let address = lease.yiaddr in
  match Dhcp_wire.find_subnet_mask lease.options with
  | None -> None
  | Some subnet ->
    let network = Ipaddr.V4.Prefix.of_netmask subnet address in
    let valid_routers =
    List.filter
      (fun ip -> Ipaddr.V4.Prefix.mem ip network)
      (Dhcp_wire.collect_routers lease.options)
    in
    match valid_routers with
    | [] -> Some (V1_LWT.{ address; network; gateway = None })
    | hd::_ -> Some (V1_LWT.{ address; network; gateway = (Some hd) })

let src = Logs.Src.create "dhcp_client"
module Log = (val Logs.src_log src : Logs.LOG)

module Make(Time : V1_LWT.TIME) (Net : V1_LWT.NETWORK) = struct
  open Lwt.Infix

  let usable_config_of_lease = function
  | None -> None
  | Some lease -> ipv4_config_of_lease lease

  let connect ?(requests : Dhcp_wire.option_code list option) (net : Net.t) : V1_LWT.ipv4_config Lwt.t =
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
      | Some lease -> Lwt.return_unit
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
    Lwt.pick [ listen (); repeater dhcpdiscover; ] >>= fun () ->
    match usable_config_of_lease (Dhcp_client.lease !c) with
    | None -> Lwt.fail_with "Couldn't obtain a usable DHCP lease"
    | Some lease -> Lwt.return lease

end
