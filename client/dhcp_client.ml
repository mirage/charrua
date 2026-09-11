(* a variant type representing the current [state] of the client transaction.
   Represented states differ from the diagram presented in RFC2131 in the
   following ways:
   The earliest state is `Selecting`.  There is no representation of INIT-REBOOT,
   REBOOTING, or INIT.  Calls to `create` will generate a client in state
   `Selecting` with the corresponding `DHCPDISCOVER` recorded, and that packet
   is exposed to the caller of `create`, who is responsible for sending it.
   There is no REBINDING state.  Clients which do not re-enter the `Bound` state
   from `Renewing` do not halt their network and re-enter the `Selecting` state.
   *)
type state  = | Selecting of Dhcp_wire.pkt (* dhcpdiscover sent *)
              | Requesting of (Dhcp_wire.pkt * Dhcp_wire.pkt) (* dhcpoffer input * dhcprequest sent *)
              | Bound of Dhcp_wire.pkt (* dhcpack received *)
              | Renewing of (Dhcp_wire.pkt * Dhcp_wire.pkt) (* dhcpack received, dhcprequest sent *)
              | Rebinding of (Dhcp_wire.pkt * Dhcp_wire.pkt option * Dhcp_wire.pkt)

(* `srcmac` will be used as the source of Ethernet frames,
   as well as the client identifier whenever one is required (e.g. padded with
   0x00 in the `chaddr` field of the BOOTP message).
   `request_options` will be sent in DHCPDISCOVER and DHCPREQUEST packets. *)
type t = {
  srcmac : Macaddr.t;
  request_options : Dhcp_wire.option_code list;
  options : Dhcp_wire.dhcp_option list;
  state  : state;
}

(* constant fields are represented here for convenience.
   This module can then be locally opened where required *)
module Constants = struct
  open Dhcp_wire
  let htype = Ethernet_10mb
  let hlen = 6 (* length of a mac address in bytes *)
  let hops = 0
  let sname = ""
  let file = ""
end

(* This are the options that Windows 10 uses in the PRL implement RFC7844.
   They are ordered by code number.
   TODO: There should be a variable in the configuration where the user
   specifies to use the Anonymity Profiles, and ignore any other option that
   would modify this static PRL.
   This PRL could be also reverted to the minimal one and be used only when
   using Anonymity Profiles.
*)
(* if the caller of `Dhcp_client.create` has not requested their own list of
   Dhcp_wire.option_code , provide a default one with the minimum set of things
   usually required for a working network connection in MirageOS. *)
let default_requests =
  Dhcp_wire.([
    SUBNET_MASK;
    ROUTERS;
    DNS_SERVERS;
    DOMAIN_NAME;
    PERFORM_ROUTER_DISC;
    STATIC_ROUTES;
    VENDOR_SPECIFIC;
    NETBIOS_NAME_SERVERS;
    NETBIOS_NODE;
    NETBIOS_SCOPE;
    CLASSLESS_STATIC_ROUTE;
    PRIVATE_CLASSLESS_STATIC_ROUTE;
    WEB_PROXY_AUTO_DISC;
  ])

(* a pretty-printer for the client, useful for debugging and logging. *)
let pp fmt p =
  let pp_state fmt = function
    | Selecting pkt -> Format.fprintf fmt "SELECTING.  Generated %a" Dhcp_wire.pp_pkt pkt
    | Requesting (received, sent) ->
      Format.fprintf fmt
        "REQUESTING. Received %a, and generated response %a"
        Dhcp_wire.pp_pkt received Dhcp_wire.pp_pkt sent
    | Bound pkt -> Format.fprintf fmt "BOUND.  Received %a" Dhcp_wire.pp_pkt pkt
    | Renewing (ack, request) ->
      Format.fprintf fmt
        "RENEWING.  Have lease %a, generated request %a"
        Dhcp_wire.pp_pkt ack Dhcp_wire.pp_pkt request
    | Rebinding (ack, _renew_request, request) ->
      Format.fprintf fmt
        "REBINDING.  Have lease %a, generated request %a"
        Dhcp_wire.pp_pkt ack Dhcp_wire.pp_pkt request
  in
  Format.fprintf fmt "%a: %a" Macaddr.pp p.srcmac pp_state p.state

(* the lease function lets callers know whether the abstract (to them) lease
   object carries a usable network configuration. *)
let lease {state; _} = match state with
  | Bound dhcpack | Renewing (dhcpack, _) | Rebinding (dhcpack, _, _) -> Some dhcpack
  | Requesting _ | Selecting _ -> None

(* a convenience function for retrieving the most recently used transaction id.
   I don't know why this is needed or useful for anyone; it should probaby be
   removed. *)
let most_recent_xid { state; _ } =
  match state with
  | Selecting p -> p.xid
  | Requesting (_i, o) -> o.xid
  | Bound a -> a.xid
  | Renewing (_i, o) -> o.xid
  | Rebinding (_i, _o, o') -> o'.xid

let xid_matches {state; _} xid =
  let open Dhcp_wire in
  let is_match xid' = Int32.equal xid xid' in
  match state with
  | Selecting p -> is_match p.xid
  | Requesting (_i, o) -> is_match o.xid
  | Bound a -> is_match a.xid
  | Renewing (_i, o) -> is_match o.xid
  | Rebinding (_i, o, o') ->
    Option.fold o ~none:false ~some:(fun o -> is_match o.xid)
    || is_match o'.xid

(* given a set of information, assemble a DHCPREQUEST packet from the Constants
   module and other constants defined in Dhcp_wire. *)
let make_request ?(srcip = Ipaddr.V4.any) ?(dstip = Ipaddr.V4.broadcast) ?(ciaddr = Ipaddr.V4.any)
    ~xid ~chaddr ~srcmac ~siaddr ~options () =
  let open Dhcp_wire in
  Constants.({
    htype; hlen; hops; sname; file;
    xid;
    chaddr;
    srcport = Dhcp_wire.client_port;
    dstport = Dhcp_wire.server_port;
    srcmac;
    srcip;
    (* destinations should still be broadcast,
     * even though we have the necessary information to send unicast,
     * because there might be >1 DHCP server on the network.
     * those who we're not responding to should know that we're in a
     * transaction to accept another lease. *)
    dstmac = Macaddr.broadcast;
    dstip;
    op = BOOTREQUEST;
    options;
    secs = 0;
    flags = Broadcast;
    ciaddr;
    yiaddr = Ipaddr.V4.any;
    siaddr;
    giaddr = Ipaddr.V4.any;
  })

(* respond to an incoming DHCPOFFER. *)
let offer (t : t) ~xid ~chaddr ~server_ip ~request_ip ~offer_options =
  let open Dhcp_wire in
  (* TODO: make sure the offer contains everything we expect before we accept it *)
  let options = [
    Message_type DHCPREQUEST;
    Request_ip request_ip;
  ] @ t.options
  in
  let options =
    match Dhcp_wire.find_server_identifier offer_options with
    | None -> options
    | Some server_ip ->
      Server_identifier server_ip :: options
  in
  let options =
    match t.request_options with
    | [] -> options (* if this is the case, the user explicitly requested it; honor that *)
    | _::_ -> (Parameter_requests t.request_options) :: options
  in
  make_request ~xid ~chaddr ~srcmac:t.srcmac ~siaddr:server_ip ~options:options ()

(* DHCPREQUEST generated during RENEWING or REBINDING state (RFC 2131 Section 4.3.2):
   - 'server identifier' MUST NOT be filled in
   - 'requested IP address' option MUST NOT be filled in
   - 'ciaddr' MUST be filled in with client's IP address
   - for RENEWING we fill siaddr and unicast, for REBINDING we broadcast
*)
let renew_request ?siaddr (t : t) ~ciaddr ~xid ~chaddr =
  let open Dhcp_wire in
  let options = [
    Message_type DHCPREQUEST;
  ] @ t.options in
  let options =
    match t.request_options with
    | [] -> options
    | _::_ -> (Parameter_requests t.request_options) :: options
  in
  let dstip, siaddr =
    (* [siaddr] being [Some _] signals we are renewing. When renewing:
       - fill siaddr and unicast to the DHCP server
       when rebinding:
       - leave siaddr all zeroes and broadcast to any DHCP server *)
    match siaddr with
    | None -> None, Ipaddr.V4.any
    | Some siaddr -> Some siaddr, siaddr
  in
  make_request ~srcip:ciaddr ?dstip ~ciaddr ~xid ~chaddr ~srcmac:t.srcmac ~siaddr ~options ()

(* make a new DHCP client. allow the user to request a specific xid, any
   requests, and the MAC address to use as the source for Ethernet messages and
   the chaddr in the fixed-length part of the message *)
let create ?(options = []) ?requests xid srcmac =
  let open Constants in
  let open Dhcp_wire in
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
      Client_id (Hwaddr srcmac);
      Parameter_requests requests;
    ] @ options;
  } in
  {srcmac; request_options = requests; options; state = Selecting pkt}, pkt

(* for a DHCP client, figure out whether an incoming packet should modify the
   state, and if a response message is warranted, generate it.
   Defined transitions are:
   Selecting -> DHCPOFFER -> Requesting
   Requesting -> DHCPACK -> Bound
   Requesting -> DHCPNAK -> Selecting
   Renewing -> DHCPACK -> Bound
   Renewing -> DHCPNAK -> Selecting
   *)
let input t buf =
  let open Dhcp_wire in
  match pkt_of_buf buf (Cstruct.length buf) with
  | Error `Not_dhcp -> `Not_dhcp
  | Error `Msg _ -> `Noop
  | Ok incoming ->
    (* RFC2131 4.4.1: respond only to messages for our xid *)
    if xid_matches t incoming.xid then begin
    match find_message_type incoming.options, t.state with
    | None, _ -> `Noop
    | Some DHCPOFFER, Selecting dhcpdiscover ->
        (* "the mechanism used to select one DHCPOFFER [is] implementation
           dependent" (RFC2131) so just take the first one *)
        let dhcprequest = offer t ~server_ip:incoming.siaddr
                          ~request_ip:incoming.yiaddr
                          ~offer_options:incoming.options
                          ~xid:dhcpdiscover.xid
                          ~chaddr:dhcpdiscover.chaddr in
        `Response ({t with state = Requesting (incoming, dhcprequest)},
                   dhcprequest)
    | Some DHCPOFFER, _ -> (* DHCPOFFER is irrelevant when we're not selecting *)
      `Noop
    | Some DHCPACK, Renewing _
    | Some DHCPACK, Rebinding _
    | Some DHCPACK, Requesting _ -> `New_lease ({t with state = Bound incoming}, incoming)
    | Some DHCPNAK, Requesting _
    | Some DHCPNAK, Renewing _
    | Some DHCPNAK, Rebinding _ ->
      `Response (create ~options:t.options ~requests:t.request_options (most_recent_xid t) t.srcmac)
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

(* try to renew the lease, probably because some time has elapsed. *)
let renew t = match t.state with
  | Selecting _ | Requesting _ | Rebinding _ -> `Noop
  | Renewing (_lease, request) -> `Response (t, request)
  | Bound lease ->
    let request = renew_request t ~ciaddr:lease.yiaddr ~xid:lease.xid ~chaddr:lease.chaddr ~siaddr:lease.siaddr in
    let state = Renewing (lease, request) in
    `Response ({t with state = state}, request)

let rebind t = match t.state with
  | Selecting _ | Requesting _ -> `Noop
  | Rebinding (_lease, _renew_request, request) -> `Response (t, request)
  | Bound lease ->
    let request = renew_request t ~ciaddr:lease.yiaddr ~xid:lease.xid ~chaddr:lease.chaddr in
    let state = Rebinding (lease, None, request) in
    `Response ({ t with state }, request)
  | Renewing (lease, old_renew_request) ->
    let request = renew_request t ~ciaddr:lease.yiaddr ~xid:lease.xid ~chaddr:lease.chaddr in
    let state = Rebinding (lease, Some old_renew_request, request) in
    `Response ({ t with state }, request)
