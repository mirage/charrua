open Lwt.Infix

(* additional tests for time- and network-dependent code *)

module No_random = struct
  type g
  let generate ?g:_ n = Cstruct.create n
end

module No_net = struct
  type error = Mirage_net.Net.error
  let pp_error = Mirage_net.Net.pp_error
  type stats = Mirage_net.stats
  type t = { mac : Macaddr.t; mutable packets : Cstruct.t list }
  let disconnect _ = Lwt.return_unit
  let write t ~size fillf =
    let buf = Cstruct.create size in
    let l = fillf buf in
    assert (l <= size);
    let b = Cstruct.sub buf 0 l in
    t.packets <- t.packets @ [b];
    Lwt.return_ok ()
  let listen _ ~header_size:_ _ = Lwt.return_ok ()
  let mac t = t.mac
  let mtu _t = 1500
  let reset_stats_counters _ = ()
  let get_stats_counters _ = {
    Mirage_net.rx_bytes = 0L;
    tx_bytes = 0L;
    rx_pkts = 0l;
    tx_pkts = 0l;
  }
  let connect ~mac () = { packets = []; mac }
  let get_packets t = t.packets
end

let keep_trying () =
  Lwt_main.run @@ (
    let module Client = Dhcp_client_lwt.Make(No_random)(No_net) in
    let net = No_net.connect ~mac:(Macaddr.of_string_exn "c0:ff:ee:c0:ff:ee") () in
    let test =
      Client.connect net >>= Lwt_stream.get >|= function
      | Some _ -> Alcotest.fail "got a lease from a nonfunctioning network somehow"
      | None -> ()
    in
    Lwt.pick [
      test;
      Lwt.pause () >>= function () ->
      (Alcotest.(check bool) "sent >1 packet" true (List.length (No_net.get_packets net) > 1); Lwt.return_unit)
    ]
  )

let () =
  Alcotest.run "lwt client tests" [
    "timeouts", [
       "more than one dhcpdiscover is sent", `Quick, keep_trying;
    ]
  ]
