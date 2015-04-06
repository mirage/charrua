(*
 * Copyright (c) 2015 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

type op =
  | Bootrequest
  | Bootreply
  | Unknown

type htype =
  | Ethernet_10mb
  | Other

type flags =
  | Broadcast
  | Ignore

type chaddr =
  | Hwaddr of Macaddr.t
  | Cliid of Bytes.t

type dhcp_option =
  | Subnet_mask of Ipaddr.V4.t              (* code 1 *)
  | Time_offset of Int32.t                  (* code 2 *)
  | Routers of Ipaddr.V4.t list             (* code 3 *)
  | Time_servers of Ipaddr.V4.t list        (* code 4 *)
  | Name_servers of Ipaddr.V4.t list        (* code 5 *)
  | Dns_servers of Ipaddr.V4.t list         (* code 6 *)
  | Log_servers of Ipaddr.V4.t list         (* code 7 *)
  | Cookie_servers of Ipaddr.V4.t list      (* code 8 *)
  | Lpr_servers of Ipaddr.V4.t list         (* code 9 *)
  | Impress_servers of Ipaddr.V4.t list     (* code 10 *)
  | Rsclocation_servers of Ipaddr.V4.t list (* code 11 *)
  | Hostname of string                      (* code 12 *)
  | Bootfile_size of int                    (* code 13 *)
  | Unknown

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
  chaddr  : chaddr;
  sname   : string;
  file    : string;
  options : dhcp_option list;
}

val pkt_min_len : int
val make_buf : unit -> Cstruct.t
val pkt_of_buf : Cstruct.t -> int -> pkt
val str_of_pkt : pkt -> string
