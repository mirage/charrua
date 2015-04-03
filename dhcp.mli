type op =
  | Bootrequest
  | Bootreply
  | Unknown

type htype =
  | Ethernet_10mb
  | Unknown

type flags =
  | Broadcast
  | Ignore

(* Describes a packed DHCP packet *)
type pkt = {
  op      : op;
  htype   : htype;
  hlen    : int;
  hops    : int;
  xid     : int32;
  secs    : int;
  flags   : flags;
  ciaddr  : Ipaddr.V4.t;
  yiaddr  : Ipaddr.V4.t;
  siaddr  : Ipaddr.V4.t;
  giaddr  : Ipaddr.V4.t;
  chaddr  : bytes;
  sname   : string;
  file    : string;
  options : bytes list;
}

val pkt_min_len : int
val make_buf : unit -> Cstruct.t
val pkt_of_buf : Cstruct.t -> int -> pkt
