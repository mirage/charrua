module Make (Network : Mirage_net.S) : sig
  type t = (Ipaddr.V4.Prefix.t * Ipaddr.V4.t option) Lwt_stream.t
  val connect : ?options:Dhcp_wire.dhcp_option list ->
    ?requests:Dhcp_wire.option_code list -> Network.t -> t Lwt.t
  (** [connect ~options ~requests net] attempts to use [net] to obtain a valid
      DHCP lease containing the DHCP option codes listed in [request].
      If [request] is not specified, [connect] uses the default values
      provided by the upstream Dhcp_client implementation, which are
      a small set useful in establishing ipv4 connectivity.
      The list of [options] will be transmitted as client options.
      [connect] does not time out; it will terminate on send/receive
      errors or when a lease is obtained.
  *)
end
