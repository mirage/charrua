open Dhcp_cpkt

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

let buf_len = 4096
let pkt_min_len = 236

let make_buf () = Cstruct.create buf_len
let check_buf_len buf len =
  if (Cstruct.len buf) <> buf_len then
    invalid_arg (Printf.sprintf "Invalid buf size %d <> %d" (Cstruct.len buf) buf_len)
  else if len < pkt_min_len then
    invalid_arg (Printf.sprintf "len too small %d < %d" len pkt_min_len)
  
let op_of_buf buf = match get_cpkt_op buf with
  | 1 -> Bootrequest
  | 2 -> Bootreply
  | _ -> Unknown

let htype_of_buf buf = match get_cpkt_htype buf with
  | 1 -> Ethernet_10mb
  | _ -> Unknown

let hlen_of_buf = get_cpkt_hlen
let hops_of_buf = get_cpkt_hops
let xid_of_buf = get_cpkt_xid
let secs_of_buf = get_cpkt_secs

(* XXX this is implying policy instead of mechanism *)
let flags_of_buf buf =
  if ((get_cpkt_flags buf) land 1) <> 0 then
    Broadcast
  else
    Ignore

let ciaddr_of_buf buf = Ipaddr.V4.of_int32 (get_cpkt_ciaddr buf)
let yiaddr_of_buf buf = Ipaddr.V4.of_int32 (get_cpkt_yiaddr buf)
let siaddr_of_buf buf = Ipaddr.V4.of_int32 (get_cpkt_siaddr buf)
let giaddr_of_buf buf = Ipaddr.V4.of_int32 (get_cpkt_giaddr buf)
let chaddr_of_buf buf = copy_cpkt_chaddr buf
let sname_of_buf buf = copy_cpkt_sname buf
let file_of_buf buf = copy_cpkt_file buf

let pkt_of_buf buf len =
  check_buf_len buf len;
  if len < pkt_min_len then
    Log.warn "packet too small (%d)" len;
  let op = op_of_buf buf in
  let htype = htype_of_buf buf in
  let hlen = hlen_of_buf buf in
  let hops = hops_of_buf buf in
  let xid = xid_of_buf buf in
  let secs = secs_of_buf buf in
  let flags = flags_of_buf buf in
  let ciaddr = ciaddr_of_buf buf in
  let yiaddr = yiaddr_of_buf buf in
  let siaddr = siaddr_of_buf buf in
  let giaddr = giaddr_of_buf buf in
  let chaddr = chaddr_of_buf buf in
  let sname = sname_of_buf buf in
  let file = file_of_buf buf in
  let options = [] in
  { op; htype; hlen; hops; xid; secs; flags; ciaddr; yiaddr;
    siaddr; giaddr; chaddr; sname; file; options }
