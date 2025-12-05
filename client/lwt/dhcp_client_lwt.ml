let src = Logs.Src.create "dhcp_client_lwt"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (Net : Mirage_net.S) = struct
  open Lwt.Infix

  type lease = Dhcp_wire.pkt

  type t = {
    lease : lease Lwt_mvar.t;
    net : Net.t;
    mutable listen : Cstruct.t -> unit Lwt.t;
    stop_condition : (unit, Net.error) result Lwt_condition.t;
    listener_condition : unit Lwt_condition.t;
  }

  let lease_mvar t = t.lease

  let connect ?(renew = true) ?xid ?options ?requests net =
    (* listener needs to occasionally check to see whether the state has advanced,
     * and if not, start a new attempt at a lease transaction *)
    let sleep_interval = Duration.of_sec 4 in
    let header_size = Ethernet.Packet.sizeof_ethernet in
    let size = Net.mtu net + header_size in

    let xid = match xid with
      | None -> Randomconv.int32 Mirage_crypto_rng.generate
      | Some xid -> xid
    in
    let (client, dhcpdiscover) = Dhcp_client.create ?options ?requests xid (Net.mac net) in
    let c = ref client in

    let rec do_renew c t =
      Mirage_sleep.ns @@ Duration.of_sec t >>= fun () ->
      match Dhcp_client.renew c with
      | `Noop -> Log.debug (fun f -> f "Can't renew this lease; won't try");  Lwt.return_unit
      | `Response (c, pkt) ->
        Log.debug (fun f -> f "attempted to renew lease: %a" Dhcp_client.pp c);
        Net.write net ~size (Dhcp_wire.pkt_into_buf pkt) >>= function
          | Error e ->
            Log.err (fun f -> f "Failed to write lease renewal request: %a" Net.pp_error e);
            Lwt.return_unit
          | Ok () ->
            do_renew c t (* ideally t would come from the new lease... *)
    in
    let rec get_lease cond dhcpdiscover =
      Log.debug (fun f -> f "Sending DHCPDISCOVER...");
      Net.write net ~size (Dhcp_wire.pkt_into_buf dhcpdiscover) >>= function
      | Error e ->
        Log.err (fun f -> f "Failed to write initial lease discovery request: %a" Net.pp_error e);
        Lwt.return_unit
      | Ok () ->
        Lwt.pick [
          Lwt_condition.wait cond;
          Mirage_sleep.ns sleep_interval;
        ] >>= fun () ->
        match Dhcp_client.lease !c with
        | Some _lease -> Lwt.return_unit
        | None ->
          let xid = Randomconv.int32 Mirage_crypto_rng.generate in
          let (client, dhcpdiscover) = Dhcp_client.create ?requests xid (Net.mac net) in
          c := client;
          Log.info (fun f -> f "Timeout expired without a usable lease!  Starting over...");
          Log.debug (fun f -> f "New lease attempt: %a" Dhcp_client.pp !c);
          get_lease cond dhcpdiscover
    in
    let listen t cond =
      Net.listen t.net ~header_size (fun buf ->
        match Dhcp_client.input !c buf with
        | `Noop ->
          Lwt.return_unit
        | `Not_dhcp ->
          t.listen buf
        | `Response (s, action) -> begin
            Net.write net ~size (Dhcp_wire.pkt_into_buf action) >>= function
            | Error e ->
              Log.err (fun f -> f "Failed to write lease transaction response: %a" Net.pp_error e);
              Lwt.return_unit
            | Ok () ->
              Log.debug (fun f -> f "State advanced! Now %a" Dhcp_client.pp s);
              c := s;
              Lwt.return_unit
        end
        | `New_lease (s, l) ->
          let open Dhcp_wire in
          (* a lease is obtained! Note it, and replace the current listener *)
          Log.info (fun f -> f "Lease obtained! IP: %a, routers: %a"
                       Ipaddr.V4.pp l.yiaddr
                       (Fmt.list Ipaddr.V4.pp) (collect_routers l.options));
          Lwt_mvar.put t.lease l >>= fun () ->
          c := s;
          Lwt_condition.broadcast cond ();
          (* TODO think more abour renewal, adjust timeouts *)
          match renew with
          | true ->
            Mirage_sleep.ns @@ Duration.of_sec 1800 >>= fun () ->
            do_renew !c 1800
          | false ->
            Lwt.return_unit
      )
    in
    let lease_wrapper t () =
      let cond = Lwt_condition.create () in
      Lwt.both
        (listen t cond >|= fun r ->
         Lwt_condition.broadcast t.stop_condition r)
        (get_lease cond dhcpdiscover)
      >|= fun ((), ()) -> ()
    in
    let lease = Lwt_mvar.create_empty () in
    let t = { lease; net; listen = Fun.const Lwt.return_unit; stop_condition = Lwt_condition.create (); listener_condition = Lwt_condition.create () } in
    Lwt.async (fun () -> lease_wrapper t ());
    Lwt.return t

  let connect_no_dhcp net =
    let lease = Lwt_mvar.create_empty () in
    let t = { lease; net; listen = Fun.const Lwt.return_unit; stop_condition = Lwt_condition.create () ; listener_condition = Lwt_condition.create ()} in
    let task =
      Lwt_condition.wait t.listener_condition >>= fun () ->
      Net.listen t.net ~header_size:Ethernet.Packet.sizeof_ethernet t.listen >|= fun r ->
      Lwt_condition.broadcast t.stop_condition r
    in
    Lwt.async (fun () -> task);
    Lwt.return t

  let listen' t fn =
    t.listen <- fn;
    Lwt_condition.broadcast t.listener_condition ();
    Lwt_condition.wait t.stop_condition

  let listen t ~header_size fn =
    (* can this ever not be ethernet?! *)
    assert (header_size = Ethernet.Packet.sizeof_ethernet);
    listen' t fn

  type error = Net.error
  let pp_error = Net.pp_error
  let disconnect t = Net.disconnect t.net
  let write t = Net.write t.net
  let mac t = Net.mac t.net
  let mtu t = Net.mtu t.net
  let get_stats_counters t = Net.get_stats_counters t.net
  let reset_stats_counters t = Net.reset_stats_counters t.net
end
