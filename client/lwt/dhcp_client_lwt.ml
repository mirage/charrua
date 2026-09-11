let src = Logs.Src.create "dhcp_client_lwt"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (Net : Mirage_net.S) = struct
  open Lwt.Infix

  type lease = Dhcp_wire.pkt

  type t = {
    lease : lease Lwt_mvar.t;
    net : Net.t;
    mutable listen : Cstruct.t -> unit Lwt.t;
    stop : (unit, Net.error) result Lwt.t;
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

    let cond = Lwt_condition.create () in

    let rec do_renew lease =
      let renewal =
        Dhcp_wire.find_renewal_t1 lease.Dhcp_wire.options
        |> Option.value ~default:1800l
        |> Int32.unsigned_to_int
        |> Option.value ~default:Int.max_int
      in
      let t2 (* rebinding *) =
        Dhcp_wire.find_rebinding_t2 lease.Dhcp_wire.options
        |> Option.value ~default:75600l (* 21h = (7/8)*24h *)
        |> Int32.unsigned_to_int
        |> Option.value ~default:Int.max_int
      in
      let expiry =
        Dhcp_wire.find_ip_lease_time lease.Dhcp_wire.options
        |> Option.value ~default:86400l (* 24h *)
        |> Int32.unsigned_to_int
        |> Option.value ~default:Int.max_int
      in
      let t2 = Mirage_sleep.ns @@ Duration.of_sec t2 in
      let expiry = Mirage_sleep.ns @@ Duration.of_sec expiry in
      let new_lease = Lwt_condition.wait cond >|= fun lease -> `Lease lease in
      Mirage_sleep.ns @@ Duration.of_sec renewal >>= fun () ->
      let rec send_renewal () =
        match Dhcp_client.renew !c with
        | `Noop -> 
          Lwt.return `Can't_renew
        | `Response (updated_c, pkt) ->
          c := updated_c;
          Log.debug (fun f -> f "attempted to renew lease: %a" Dhcp_client.pp updated_c);
          Net.write net ~size (Dhcp_wire.pkt_into_buf pkt) >>= function
          | Error e ->
            Lwt.return (`Failed_to_write e)
          | Ok () ->
            Mirage_sleep.ns sleep_interval >>= send_renewal
      in
      Lwt.pick [
        new_lease;
        send_renewal ();
        (t2 >|= fun () -> `T2_rebinding);
        (expiry >|= fun () -> `Expired);
      ] >>= function
      | `Lease lease ->
        do_renew lease
      | `Can't_renew ->
        Log.debug (fun f -> f "Can't renew this lease; won't try");
        Lwt.return_unit
      | `T2_rebinding ->
        do_rebind expiry
      | `Expired ->
        Log.warn (fun f -> f "Lease expired before we could renew");
        failwith "DHCP lease expired"
      | `Failed_to_write e ->
        Log.err (fun f -> f "Failed to write lease renewal request: %a" Net.pp_error e);
        Lwt.return_unit
    and do_rebind expiry =
      let new_lease = Lwt_condition.wait cond >|= fun lease -> `Lease lease in
      let rec send_rebind () =
        match Dhcp_client.rebind !c with
        | `Noop ->
          Lwt.return `Can't_renew
        | `Response (updated_c, pkt) ->
          c := updated_c;
          Log.debug (fun f -> f "attempted to rebind lease: %a" Dhcp_client.pp updated_c);
          Net.write net ~size (Dhcp_wire.pkt_into_buf pkt) >>= function
          | Error e ->
            Lwt.return (`Failed_to_write e)
          | Ok () ->
            Mirage_sleep.ns sleep_interval >>= send_rebind
      in
      Lwt.pick [
        new_lease;
        send_rebind ();
        (expiry >|= fun () -> `Expired);
      ] >>= function
      | `Lease lease ->
        do_renew lease
      | `Can't_renew ->
        Log.debug (fun f -> f "Can't renew this lease; won't try");
        Lwt.return_unit
      | `Expired ->
        Log.warn (fun f -> f "Lease expired before we could renew");
        failwith "DHCP lease expired"
      | `Failed_to_write e ->
        Log.err (fun f -> f "Failed to write lease renewal request: %a" Net.pp_error e);
        Lwt.return_unit
    in
    let rec get_lease cond dhcpdiscover =
      Log.debug (fun f -> f "Sending DHCPDISCOVER...");
      Net.write net ~size (Dhcp_wire.pkt_into_buf dhcpdiscover) >>= function
      | Error e ->
        Log.err (fun f -> f "Failed to write initial lease discovery request: %a" Net.pp_error e);
        Lwt.return_unit
      | Ok () ->
        Lwt.pick [
          (Lwt_condition.wait cond >|= fun lease -> `Lease lease);
          (Mirage_sleep.ns sleep_interval >|= fun () -> `Timeout);
        ] >>= function
        | `Lease lease ->
          if renew then
            do_renew lease
          else Lwt.return_unit
        | `Timeout ->
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
          Lwt_condition.broadcast cond l;
          Lwt.return_unit
      )
    in
    let lease_wrapper t stop_waker =
      Lwt.all
        [
        (listen t cond >|= fun r ->
         Lwt.wakeup_later stop_waker r);
        (get_lease cond dhcpdiscover);
      ]
      >|= fun _units -> ()
    in
    let lease = Lwt_mvar.create_empty () in
    let stop, stop_waker = Lwt.task () in
    let t = { lease; net; listen = Fun.const Lwt.return_unit; stop; listener_condition = Lwt_condition.create () } in
    Lwt.async (fun () -> lease_wrapper t stop_waker);
    Lwt.return t

  let connect_no_dhcp net =
    let lease = Lwt_mvar.create_empty () in
    let stop, stop_waker = Lwt.task () in
    let t = { lease; net; listen = Fun.const Lwt.return_unit; stop ; listener_condition = Lwt_condition.create ()} in
    let task =
      Lwt_condition.wait t.listener_condition >>= fun () ->
      let listen frame = t.listen frame in
      Net.listen t.net ~header_size:Ethernet.Packet.sizeof_ethernet listen >|= fun r ->
      Lwt.wakeup_later stop_waker r
    in
    Lwt.async (fun () -> task);
    Lwt.return t

  let listen' t fn =
    t.listen <- fn;
    Lwt_condition.broadcast t.listener_condition ();
    (* Callers of listen don't expect cancelling to cancel all other calls on
       listen. So we return a [_ Lwt.t] that can't cancel [t.stop]. *)
    Lwt.protected t.stop

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
