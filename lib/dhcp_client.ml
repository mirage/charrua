type t = | Selecting of Dhcp_wire.pkt (* dhcpdiscover sent *)
         | Requesting of (Dhcp_wire.pkt * Dhcp_wire.pkt) (* dhcpoffer input * dhcprequest sent *)
         | Bound of Dhcp_wire.pkt (* dhcpack received *)
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
  match p with
  | Selecting pkt -> Format.fprintf fmt "SELECTING.  Generated %s" @@ pr pkt
  | Requesting (received, sent) -> Format.fprintf fmt
      "REQUESTING. Received %s, and generated response %s" (pr received) (pr sent)
  | Bound pkt -> Format.fprintf fmt "BOUND.  Received %s" @@ pr pkt

let lease = function
  | Bound dhcpack -> Some dhcpack
  | Requesting _ | Selecting _ -> None

let offer ~dhcpdiscover ~dhcpoffer () =
  let open Dhcp_wire in
  (* TODO: make sure the offer contains everything we expect before we accept it *)
  let options = [
    Message_type DHCPREQUEST;
    Request_ip dhcpoffer.yiaddr;
    Server_identifier dhcpoffer.siaddr;
  ] in
  let options =
    match find_parameter_requests dhcpdiscover.options with
    | None -> options (* if this is the case, the user explicitly requested it; honor that *)
    | Some p -> (Parameter_requests p) :: options
  in
  let dhcprequest = Constants.({
    htype; hlen; hops; sname; file;
    xid = dhcpoffer.xid;
    chaddr = dhcpdiscover.chaddr;
    srcport = Dhcp_wire.client_port;
    dstport = Dhcp_wire.server_port;
    srcmac = dhcpdiscover.srcmac;
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
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = dhcpoffer.siaddr;
    giaddr = Ipaddr.V4.any;
  }) in
  Requesting (dhcpoffer, dhcprequest), Some (Dhcp_wire.buf_of_pkt dhcprequest)

let respond_if t ~msgtype pkt f =
  let open Dhcp_wire in
  match find_message_type pkt.options with
  | None -> (t, None)
  | Some m when m = msgtype -> f ()
  | Some _ -> (t, None)

let safe_pkt_of_buf buf len =
  try Dhcp_wire.pkt_of_buf buf len
  with exn -> Error (Printexc.to_string exn)

let input t buf =
  let open Dhcp_wire in
  match safe_pkt_of_buf buf (Cstruct.len buf) with
  | Error _ -> (t, None)
  | Ok incoming ->
    match t with
    | Selecting dhcpdiscover when incoming.xid = dhcpdiscover.xid ->
      respond_if t ~msgtype:DHCPOFFER incoming @@ offer ~dhcpdiscover ~dhcpoffer:incoming
    | Requesting (_dhcpoffer, dhcprequest) when incoming.xid = dhcprequest.xid ->
      respond_if t ~msgtype:DHCPACK incoming (fun () -> (Bound incoming , None))
    | Selecting _ | Requesting _ | Bound _ -> (t, None)

let create ?(requests = default_requests) mac =
  let open Constants in
  Stdlibrandom.initialize ();
  let xid = Cstruct.BE.get_uint32 (Stdlibrandom.generate 4) 0 in
  let pkt = Dhcp_wire.({
    htype; hlen; hops; sname; file;
    srcmac = mac;
    dstmac = Macaddr.broadcast;
    srcip = Ipaddr.V4.any;
    dstip = Ipaddr.V4.broadcast;
    srcport = Dhcp_wire.client_port;
    dstport = Dhcp_wire.server_port;
    op = BOOTREQUEST;
    xid;
    secs = 0;
    flags = Broadcast;
    ciaddr = Ipaddr.V4.any;
    yiaddr = Ipaddr.V4.any;
    siaddr = Ipaddr.V4.any;
    giaddr = Ipaddr.V4.any;
    chaddr = mac;
    options = Dhcp_wire.([
      Message_type DHCPDISCOVER;
      Parameter_requests requests;
    ]);
  }) in
  (Selecting pkt), (Dhcp_wire.buf_of_pkt pkt)
