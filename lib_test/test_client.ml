let cstruct = Alcotest.of_pp Cstruct.hexdump_pp

let msgtype =
  let module M = struct
    type t = Dhcp_wire.msgtype
    let pp fmt m = Format.fprintf fmt "%s" (Dhcp_wire.msgtype_to_string m)
    let equal p q = (compare p q) = 0
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

module Defaults = struct
  let client_mac = Macaddr.of_string_exn "00:16:3e:ba:eb:ba"
  let server_mac = Macaddr.of_string_exn "00:16:3e:00:00:00"
  let server_ip = Ipaddr.V4.of_string_exn "192.168.1.1"
  let server_network = Ipaddr.V4.Prefix.make 24 server_ip
  let range = Some (Ipaddr.V4.of_string_exn "192.168.1.15", Ipaddr.V4.of_string_exn "192.168.1.65")
  let options = []
  let config = Dhcp_server.Config.make
    ?hostname:None ?default_lease_time:None
    ?max_lease_time:None ?hosts:None
    ~addr_tuple:(server_ip, server_mac)
    ~network:server_network ~range ~options
  let empty_db = Dhcp_server.Lease.make_db ()
end

let no_result t buf () =
  let res = Client.input t buf in
  Alcotest.(check (option cstruct)) "no action" None (snd res)
;;

let parseable buf = 
  Alcotest.(check bool) "buffer we constructed is valid dhcp" true (Dhcp_wire.is_dhcp buf (Cstruct.len buf))

let start_makes_dhcp () =
  let (_s, buf) = Client.create ~mac:Defaults.client_mac in
  (* for now, any positive result is fine *)
  parseable buf

let client_to_selecting () =
  let open Defaults in
  let (s, buf) = Client.create ~mac:client_mac in
  let answer = Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
  Alcotest.(check (result pass reject)) "input succeeds" answer answer;
  (s, Rresult.R.get_ok answer)

let assert_reply p =
  let open Dhcp_server.Input in
  match p with
  | Warning s | Error s -> Alcotest.fail s
  | Silence -> Alcotest.fail "Silence from the server in response to a request"
  | Update _db -> Alcotest.fail "database update but no reply -- in our context this is likely a bug"
  | Reply (pkt, db) -> (pkt, db)

let server_accepts_start_packet () =
  let open Defaults in
  let (_, dhcpdiscover) = client_to_selecting () in
  ignore @@ assert_reply @@ Dhcp_server.Input.input_pkt config empty_db dhcpdiscover 0.

let server_gives_dhcpoffer () =
  let open Defaults in
  let open Dhcp_wire in
  let (_, dhcpdiscover) = client_to_selecting () in
  let (pkt, _db) = assert_reply @@
    Dhcp_server.Input.input_pkt config empty_db dhcpdiscover 0. in
  Alcotest.(check (option msgtype)) "initial message merited a DHCPOFFER"
    (Some DHCPOFFER) (find_message_type pkt.options)

let client_rejects_wrong_xid () =
  let open Defaults in
  let (s, answer) = client_to_selecting () in
  let (pkt, _db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db answer 0. in
  let pkt = Dhcp_wire.({pkt with xid = Int32.add pkt.xid 1l}) in
  Alcotest.(check (option cstruct)) "don't respond to dhcpoffer with non-matching xid"
    None (snd @@ Client.input s @@ Dhcp_wire.buf_of_pkt pkt)

let client_asks_dhcprequest () =
  let open Dhcp_wire in
  let open Defaults in
  let (s, answer) = client_to_selecting () in
  let (pkt, _db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db answer 0. in
  match find_message_type pkt.options with
  | Some DHCPOFFER -> begin
    match snd @@ Client.input s (Dhcp_wire.buf_of_pkt pkt) with
    | None -> Alcotest.fail "response to DHCPOFFER was silence"
    | (Some (buf)) ->
      parseable buf;
      let dhcprequest = Rresult.R.get_ok @@ Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
      Alcotest.(check (option msgtype)) "responded to DHCPOFFER with DHCPREQUEST"
        (Some DHCPREQUEST) (find_message_type dhcprequest.options)
  end
  | _ -> Alcotest.fail "couldn't get a valid DHCPOFFER to attempt to send DHCPREQUEST in response to"

let server_gives_dhcpack () =
  let open Dhcp_wire in
  let open Defaults in
  let (s, dhcpdiscover) = client_to_selecting () in
  let (dhcpoffer, db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db dhcpdiscover 0. in
  match Client.input s (Dhcp_wire.buf_of_pkt dhcpoffer) with
  | (_, None) -> Alcotest.fail "couldn't get client to respond to DHCPOFFER"
  | (_s, Some (buf)) ->
    let dhcprequest = Rresult.R.get_ok @@ Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
    let (dhcpack, _db) = assert_reply @@ Dhcp_server.Input.input_pkt config db dhcprequest 0. in
      Alcotest.(check (option msgtype)) "got a DHCPACK in response to DHCPREQUEST"
        (Some DHCPACK) (find_message_type dhcpack.options)

let client_returns_lease () =
  let open Dhcp_wire in
  let open Defaults in
  let (s, dhcpdiscover) = client_to_selecting () in
  let (dhcpoffer, db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db dhcpdiscover 0. in
  match Client.input s (Dhcp_wire.buf_of_pkt dhcpoffer) with
  | (_, None) -> Alcotest.fail "couldn't get client to respond to DHCPOFFER"
  | (s, Some (buf)) ->
    let dhcprequest = Rresult.R.get_ok @@ Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
    let (dhcpack, _db) = assert_reply @@ Dhcp_server.Input.input_pkt config db dhcprequest 0. in
    Alcotest.(check (option msgtype)) "got a DHCPACK in response to DHCPREQUEST"
      (Some DHCPACK) (find_message_type dhcpack.options);
    match Client.input s (Dhcp_wire.buf_of_pkt dhcpack) with
    | _s, Some (_) ->
       Alcotest.fail "client wanted to send more packets after receiving DHCPACK"
    | s, None ->
       Alcotest.(check (option pass)) "lease is held" (Some dhcpack) (Client.lease s)

let resultless =
  let c = Client.create ~mac:Defaults.client_mac in
  "no result for empty buffers", `Quick, (fun () -> no_result (fst c) (Cstruct.create 0) ())

let random_buffer () =
  let sz = Cstruct.BE.get_uint16 (Stdlibrandom.generate 2) 0 in
  Stdlibrandom.generate sz

let rec random_init =
  let c = Client.create ~mac:Defaults.client_mac in
  let buf = random_buffer () in
  "random buffer entry to INIT client", `Quick, (fun () -> no_result (fst c) buf ())

let rec random_selecting =
  let open Defaults in
  let (s, buf) = Client.create ~mac:client_mac in
  let offer = Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
  let offer = Rresult.R.get_ok offer in
  let (s, _) = Client.input s (Dhcp_wire.buf_of_pkt offer) in
  (* client should now be in SELECTING; feed it some random garbage *)
  "random buffer entry to SELECTING client", `Quick, (fun () -> no_result s buf ())

let rec random_requesting =
  let open Defaults in
  let (s, buf) = Client.create ~mac:client_mac in
  let dhcpdiscover = Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
  let answer = Rresult.R.get_ok dhcpdiscover in
  let (pkt, _db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db answer 0. in
  let (s, dhcprequest) = Client.input s (Dhcp_wire.buf_of_pkt pkt) in
  Alcotest.(check (option pass)) "client is in REQUESTING" dhcprequest dhcprequest;
  "random buffer entry to REQUESTING client", `Quick, (no_result s buf)

let rec random_bound =
  let open Defaults in
  let (s, buf) = Client.create ~mac:client_mac in
  let dhcpdiscover = Rresult.R.get_ok @@ Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) in
  let (pkt, db) = assert_reply @@ Dhcp_server.Input.input_pkt config empty_db dhcpdiscover 0. in
  let (s, dhcprequest) = Client.input s (Dhcp_wire.buf_of_pkt pkt) in
  match dhcprequest with
  | None -> Alcotest.fail "couldn't get client to REQUESTING"
  | Some dhcprequest ->
  let dhcprequest = Rresult.R.get_ok @@ Dhcp_wire.pkt_of_buf dhcprequest (Cstruct.len dhcprequest) in
  let (dhcpack, db) = assert_reply @@ Dhcp_server.Input.input_pkt config db dhcprequest 0. in
  let (s, response) = Client.input s (Dhcp_wire.buf_of_pkt dhcpack) in
  Alcotest.(check (option pass)) "client is in BOUND" response response;
    "random buffer entry to BOUND client", `Quick, (no_result s buf)
  
let () = 
  Alcotest.run "client tests" [
    "fuzzes", [
        resultless;
        random_init;
        random_selecting;
        random_requesting;
        random_bound;
    ];
    "state progression", [
       "initializing state machine generates a dhcp packet", `Quick, start_makes_dhcp;
       "dhcp server accepts start packet", `Quick, server_accepts_start_packet;
       "dhcp client doesn't accept DHCPOFFER with wrong xid", `Quick, client_rejects_wrong_xid;
       "dhcp server offers a lease in response to start packet", `Quick, server_gives_dhcpoffer;
       "dhcp client sends a dhcp packet in response to DHCPOFFER", `Quick, client_asks_dhcprequest;
       "dhcp server sends a DHCPACK in response to client DHCPREQUEST", `Quick, server_gives_dhcpack;
       "dhcp client returns lease after receiving DHCPACK", `Quick, client_returns_lease;
      ]
    ]
