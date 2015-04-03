val sizeof_cpkt : int
val get_cpkt_op : Cstruct.t -> Cstruct.uint8
val set_cpkt_op : Cstruct.t -> Cstruct.uint8 -> unit
val get_cpkt_htype : Cstruct.t -> Cstruct.uint8
val set_cpkt_htype : Cstruct.t -> Cstruct.uint8 -> unit
val get_cpkt_hlen : Cstruct.t -> Cstruct.uint8
val set_cpkt_hlen : Cstruct.t -> Cstruct.uint8 -> unit
val get_cpkt_hops : Cstruct.t -> Cstruct.uint8
val set_cpkt_hops : Cstruct.t -> Cstruct.uint8 -> unit
val get_cpkt_xid : Cstruct.t -> Cstruct.uint32
val set_cpkt_xid : Cstruct.t -> Cstruct.uint32 -> unit
val get_cpkt_secs : Cstruct.t -> Cstruct.uint16
val set_cpkt_secs : Cstruct.t -> Cstruct.uint16 -> unit
val get_cpkt_flags : Cstruct.t -> Cstruct.uint16
val set_cpkt_flags : Cstruct.t -> Cstruct.uint16 -> unit
val get_cpkt_ciaddr : Cstruct.t -> Cstruct.uint32
val set_cpkt_ciaddr : Cstruct.t -> Cstruct.uint32 -> unit
val get_cpkt_yiaddr : Cstruct.t -> Cstruct.uint32
val set_cpkt_yiaddr : Cstruct.t -> Cstruct.uint32 -> unit
val get_cpkt_siaddr : Cstruct.t -> Cstruct.uint32
val set_cpkt_siaddr : Cstruct.t -> Cstruct.uint32 -> unit
val get_cpkt_giaddr : Cstruct.t -> Cstruct.uint32
val set_cpkt_giaddr : Cstruct.t -> Cstruct.uint32 -> unit
val get_cpkt_chaddr : Cstruct.t -> Cstruct.t
val copy_cpkt_chaddr : Cstruct.t -> string
val set_cpkt_chaddr : string -> int -> Cstruct.t -> unit
val blit_cpkt_chaddr : Cstruct.t -> int -> Cstruct.t -> unit
val get_cpkt_sname : Cstruct.t -> Cstruct.t
val copy_cpkt_sname : Cstruct.t -> string
val set_cpkt_sname : string -> int -> Cstruct.t -> unit
val blit_cpkt_sname : Cstruct.t -> int -> Cstruct.t -> unit
val get_cpkt_file : Cstruct.t -> Cstruct.t
val copy_cpkt_file : Cstruct.t -> string
val set_cpkt_file : string -> int -> Cstruct.t -> unit
val blit_cpkt_file : Cstruct.t -> int -> Cstruct.t -> unit
(* val get_cpkt_options : Cstruct.t -> Cstruct.t *)
(* val copy_cpkt_options : Cstruct.t -> string *)
(* val set_cpkt_options : string -> int -> Cstruct.t -> unit *)
(* val blit_cpkt_options : Cstruct.t -> int -> Cstruct.t -> unit *)
val hexdump_cpkt_to_buffer : Buffer.t -> Cstruct.t -> unit
val hexdump_cpkt : Cstruct.t -> unit
