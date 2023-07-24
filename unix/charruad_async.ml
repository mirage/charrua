open! Core
open! Async
open Deferred.Let_syntax
module Unix = Core_unix

let () = Printexc.record_backtrace true
let filter_map f l = List.filter_map ~f l
let start_time = Time_ns.now ()

(* Drop privileges and chroot to _charruad home *)
let go_safe user group =
  let pw, _gr =
    try (Unix.Passwd.getbyname_exn user, Unix.Group.getbyname_exn group)
    with _ ->
      failwith "No user and/or group _charruad found, please create them."
  in
  Unix.chroot pw.dir;
  Unix.chdir "/";
  (* Unix.setproctitle "charruad"; XXX implement me *)
  let ogid = Unix.getgid () in
  let ouid = Unix.getuid () in
  Unix.setgid pw.gid;
  Unix.setuid pw.uid;
  if ogid = pw.gid || ouid = pw.uid then
    failwith "Unexpected uid or gid after dropping privileges";
  (* Make sure we cant restore the old gid and uid *)
  let canrestore =
    try
      Unix.setuid ouid;
      Unix.setgid ogid;
      true
    with _ -> false
  in
  if canrestore then failwith "Was able to restore UID, setuid is broken"

let read_file = Reader.file_contents
let go_daemon = Daemon.daemonize

let uptime_in_sec () =
  Time_ns.diff (Time_ns.now ()) start_time
  |> Time_ns.Span.to_sec |> Int.of_float

let maybe_gc db now gbcol =
  match now - gbcol >= 60 with
  | false -> return (db, gbcol)
  | true ->
      Log.Global.debug_s [%message "Garbage collecting..."];
      return
        ( Dhcp_server.Lease.garbage_collect db ~now:(Int32.of_int_exn now),
          now + 60 )

let rec input config db link gbcol =
  let open Dhcp_server.Input in
  let%bind buf = Async_rawlink.read_packet link in
  let now = uptime_in_sec () in
  maybe_gc db now gbcol >>= fun (db, gbcol) ->
  let t =
    match Dhcp_wire.pkt_of_buf buf (Cstruct.length buf) with
    | Error e ->
        Log.Global.error_s [%message e];
        return db
    | Ok pkt -> (
        Log.Global.debug_s
          [%message "Received packet: " (Dhcp_wire.pkt_to_string pkt : string)];

        match input_pkt config db pkt (Int32.of_int_exn now) with
        | Silence -> return db
        | Update db -> return db
        | Reply (reply, db) ->
            let%bind () =
              Async_rawlink.send_packet link (Dhcp_wire.buf_of_pkt reply)
            in
            Log.Global.debug_s
              [%message
                "Sent reply packet: " (Dhcp_wire.pkt_to_string reply : string)];
            return db
        | Warning w ->
            Log.Global.info_s [%message w];
            return db
        | Error e ->
            Log.Global.error_s [%message e];
            return db)
  in
  t >>= fun db -> input config db link gbcol

let ifname_of_address ip_addr interfaces =
  let ifnet =
    List.find_exn
      ~f:(function
        | _name, cidr ->
            Ipaddr.V4.compare ip_addr (Ipaddr.V4.Prefix.address cidr) = 0)
      interfaces
  in
  fst ifnet

let charruad ~configfile ~group ~pidfile ~user ~daemonize =
  let open Dhcp_server.Config in
  let open Dhcp_server.Lease in
  let interfaces = Tuntap.getifaddrs_v4 () in
  let addresses =
    List.map
      ~f:(function
        | name, cidr -> (Ipaddr.V4.Prefix.address cidr, Tuntap.get_macaddr name))
      interfaces
  in
  let%bind configtxt = read_file configfile in
  (* let config = parse configtxt addresses in *)
  let db = make_db () in
  if daemonize then go_daemon ();
  Log.Global.info_s [%message "Charrua DHCPD starting"];
  (* Filter out the addresses which have networks assigned *)
  let threads =
    filter_map
      (fun addr_tuple ->
        let addr = fst addr_tuple in
        let s = Ipaddr.V4.to_string addr in
        let config =
          try Some (parse configtxt addr_tuple) with Not_found_s _ -> None
        in
        match config with
        | Some config ->
            Log.Global.info_s [%message "Found network for " s];
            (* Get a rawlink on the interface *)
            let ifname = ifname_of_address addr interfaces in
            let link =
              Async_rawlink.(open_link ~filter:(dhcp_server_filter ()) ifname)
            in
            (* Create a thread *)
            Some (input config db link (uptime_in_sec ()))
        | None ->
            let () = Log.Global.info_s [%message "No network found for " s] in
            None)
      addresses
  in
  if List.length threads = 0 then
    failwith "Could not match any interface address with any network section.";
  (* Open pidfile before dropping priviledges *)
  let%bind pidc = Writer.open_file pidfile in
  go_safe user group;
  fprintf pidc "%d" (Unix.getpid () |> Pid.to_int);
  let%bind () = Writer.close pidc in
  Async.Deferred.all_unit threads

(* Parse command line and start the ball *)
let command =
  Command.async ~summary:"Charrua DHCPD"
    (let%map_open.Command () =
       Log_extended.Command.setup_via_params ~default_output_level:`Info
         ~log_to_console_by_default:(Log_extended.Command.Stdout Color)
         ~log_to_syslog_by_default:true ()
     and configfile =
       flag "-config"
         (optional_with_default "/etc/charruad.conf" string)
         ~doc:"Configuration file path."
     and user =
       flag "-user"
         (optional_with_default "_charruad" string)
         ~doc:"User to run as."
     and group =
       flag "-group"
         (optional_with_default "_charruad" string)
         ~doc:"Group to run as."
     and pidfile =
       flag "-pidfile"
         (optional_with_default "/run/charruad.pid" string)
         ~doc:"Pid file path."
     and daemonize = flag "-daemon" no_arg ~doc:"Daemonize." in
     fun () -> charruad ~configfile ~user ~group ~pidfile ~daemonize)

let () = Command_unix.run ~version:"%%VERSION%%" command
