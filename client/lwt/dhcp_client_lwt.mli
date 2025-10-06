module Make (Net : Mirage_net.S) : sig
  include Mirage_net.S

  type lease = Dhcp_wire.pkt

  val lease_stream : t -> lease Lwt_stream.t

  val connect : ?renew:bool -> ?xid:Cstruct.uint32 ->
    ?options:Dhcp_wire.dhcp_option list ->
    ?requests:Dhcp_wire.option_code list -> Net.t -> t Lwt.t
  (** [connect ~renew ~xid ~options ~requests net] starts a DHCP client communicating
      over the network interface [net].  The client will attempt to get a DHCP
      lease at least once, and will return any leases obtained in the stream
      returned by [connect].  If [renew] is true, which it is by default,
      the client will attempt to renew the lease according to the logic in
      RFC2131.  If [renew] is false, the client will cancel its listener and end
      the stream once the first lease has been obtained. The [options] are the
      DHCP options sent by the client in the DHCP DISCOVER and DHCP REQUEST. The
      [requests] will be transmitted as DHCP parameter request also in the DHCP
      DISCOVER and DHCP REQUEST. *)
end
