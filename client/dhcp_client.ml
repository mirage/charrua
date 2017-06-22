type state  = | Selecting of Dhcp_wire.pkt (* dhcpdiscover sent *)
              | Requesting of (Dhcp_wire.pkt * Dhcp_wire.pkt) (* dhcpoffer input * dhcprequest sent *)
              | Bound of Dhcp_wire.pkt (* dhcpack received *)
              | Renewing of (Dhcp_wire.pkt * Dhcp_wire.pkt) (* dhcpack received, dhcprequest sent *)
type t = {
  srcmac : Macaddr.t;
  request_options : Dhcp_wire.option_code list;
  xid : Cstruct.uint32;
  state  : state;
}

type buffer = Cstruct.t

(* some fields are constant *)
module Constants = struct
  open Dhcp_wire
  let htype = Ethernet_10mb
  let hlen = 6 (* length of a mac address in bytes *)
  let hops = 0
  let sname = ""
  let file = ""
end

let default_requests =
  Dhcp_wire.([
    SUBNET_MASK;
    ROUTERS;
    DNS_SERVERS;
    SERVER_IDENTIFIER;
  ])

let pp fmt p =
  let pr = Dhcp_wire.pkt_to_string in
  let pp_state fmt = function
    | Selecting pkt -> Format.fprintf fmt "SELECTING.  Generated %s" @@ pr pkt
    | Requesting (received, sent) -> Format.fprintf fmt
        "REQUESTING. Received %s, and generated response %s" (pr received) (pr sent)
    | Bound pkt -> Format.fprintf fmt "BOUND.  Received %s" @@ pr pkt
    | Renewing (ack, request) -> Format.fprintf fmt
        "RENEWING.  Have lease %s, generated request %s" (pr ack) (pr request)
  in
  Format.fprintf fmt "%s: %a" (Macaddr.to_string p.srcmac) pp_state p.state

let lease {state; _} = match state with
  | Bound dhcpack | Renewing (dhcpack, _) -> Some dhcpack
  | Requesting _ | Selecting _ -> None

let xid {state; _} =
  let open Dhcp_wire in
  match state with
  | Selecting p -> p.xid
  | Requesting (_i, o) -> o.xid
  | Bound a -> a.xid
  | Renewing (_i, o) -> o.xid

let make_request ?(ciaddr = Ipaddr.V4.any) ~xid ~chaddr ~srcmac ~siaddr ~options () =
  let open Dhcp_wire in
  Constants.({
    htype; hlen; hops; sname; file;
    xid;
    chaddr;
    srcport = Dhcp_wire.client_port;
    dstport = Dhcp_wire.server_port;
    srcmac;
    srcip = Ipaddr.V4.any;
    (* destinations should still be broadcast,
     * even though we have the necessary information to send unicast,
     * because there might be >1 DHCP server on the network.
     * those who we're not responding to should know that we're in a
     * transaction to accept another lease. *)
    dstmac = Macaddr.broadcast;
    dstip = Ipaddr.V4.broadcast;
    op = BOOTREQUEST;
    options;
    secs = 0;
    flags = Broadcast;
    ciaddr;
    yiaddr = Ipaddr.V4.any;
    siaddr;
    giaddr = Ipaddr.V4.any;
  })

let offer t ~xid ~chaddr ~server_ip ~request_ip ~offer_options =
  let open Dhcp_wire in
  (* TODO: make sure the offer contains everything we expect before we accept it *)
  let options = [
    Message_type DHCPREQUEST;
    Request_ip request_ip;
    Server_identifier server_ip;
  ] in
  let options =
    match t.request_options with
    | [] -> options (* if this is the case, the user explicitly requested it; honor that *)
    | _::_ -> (Parameter_requests t.request_options) :: options
  in
  make_request ~xid ~chaddr ~srcmac:t.srcmac ~siaddr:server_ip ~options:options ()

let create ?with_xid ?requests srcmac =
  let open Constants in
  let open Dhcp_wire in
  let xid = match with_xid with
  | None -> Stdlibrandom.initialize (); Cstruct.BE.get_uint32 (Stdlibrandom.generate 4) 0
  | Some xid -> xid
  in
  let requests = match requests with
  | None | Some [] -> default_requests
  | Some requests -> requests
  in
  let pkt = {
    htype; hlen; hops; sname; file;
    srcmac;
    dstmac = Macaddr.broadcast;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = client_port;
    dstport = server_port;
    op = BOOTREQUEST;
    xid;
    secs = 0;
    flags = Broadcast;
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = srcmac;
    options = [
      Message_type DHCPDISCOVER;
      Parameter_requests requests;
    ];
  } in
  {srcmac; xid; request_options = requests; state = Selecting pkt},
    Dhcp_wire.buf_of_pkt pkt

let input t buf =
  let open Dhcp_wire in
  match pkt_of_buf buf (Cstruct.len buf) with
  | Error _ -> `Noop
  | Ok incoming ->
    if compare incoming.xid (xid t) = 0 then begin
    match find_message_type incoming.options, t.state with
    | None, _ -> `Noop
    | Some DHCPOFFER, Selecting dhcpdiscover ->
        let dhcprequest = offer t ~server_ip:incoming.siaddr
                          ~request_ip:incoming.yiaddr
                          ~offer_options:incoming.options
                          ~xid:dhcpdiscover.xid
                          ~chaddr:dhcpdiscover.chaddr in
        `Response ({t with state = Requesting (incoming, dhcprequest)},
          (Dhcp_wire.buf_of_pkt dhcprequest))
    | Some DHCPOFFER, _ -> (* DHCPOFFER is irrelevant when we're not selecting *)
      `Noop
    | Some DHCPACK, Renewing _
    | Some DHCPACK, Requesting _ -> `New_lease ({t with state = Bound incoming}, incoming)
    | Some DHCPNAK, Requesting _ | Some DHCPNAK, Renewing _ ->
      `Response (create ~with_xid:t.xid ~requests:t.request_options t.srcmac)
    | Some DHCPACK, Selecting _ (* too soon *)
    | Some DHCPACK, Bound _ -> (* too late *)
      `Noop
    | Some DHCPDISCOVER, _ | Some DHCPDECLINE, _ | Some DHCPRELEASE, _
    | Some DHCPINFORM, _ | Some DHCPREQUEST, _ ->
      (* we don't need to care about these client messages *)
      `Noop
    | Some DHCPNAK, Selecting  _| Some DHCPNAK, Bound _ -> `Noop (* irrelevant *)
    | Some DHCPLEASEQUERY, _ | Some DHCPLEASEUNASSIGNED, _
    | Some DHCPLEASEUNKNOWN, _ | Some DHCPLEASEACTIVE, _
    | Some DHCPBULKLEASEQUERY, _ | Some DHCPLEASEQUERYDONE, _ ->
      (* these messages are for relay agents to extract information from servers;
       * our client does not care about them and shouldn't reply *)
      `Noop
    | Some DHCPFORCERENEW, _ -> `Noop (* unsupported *)
    end else `Noop

let renew t = match t.state with
  | Selecting _ | Requesting _ -> `Noop
  | Renewing (_lease, request) -> `Response (t, Dhcp_wire.buf_of_pkt request)
  | Bound lease ->
    let open Dhcp_wire in
    let request = offer t ~xid:lease.xid ~chaddr:lease.chaddr
      ~server_ip:lease.siaddr ~request_ip:lease.yiaddr
      ~offer_options:lease.options in
    let state = Renewing (lease, request) in
    `Response ({t with state = state}, (Dhcp_wire.buf_of_pkt request))
