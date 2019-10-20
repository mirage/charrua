module Make(Random : Mirage_random.S)(Time : Mirage_time.S) (Network : Mirage_net.S) : sig
  type t = Mirage_protocols.ipv4_config Lwt_stream.t
  val connect : ?requests:Dhcp_wire.option_code list
    -> Network.t -> t Lwt.t
  (** [connect ?requests net] attempts to use [net] to obtain a valid
   *  DHCP lease containing the DHCP option codes listed in [request].
   *  If [request] is not specified, [connect] uses the default values
   *  provided by the upstream Dhcp_client implementation, which are
   *  a small set useful in establishing ipv4 connectivity.
   *  [connect] does not time out; it will terminate on send/receive
   *  errors or when a lease is obtained.
   *  *)
end
