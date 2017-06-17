val ipv4_config_of_lease :
  Dhcp_wire.pkt -> Mirage_protocols_lwt.ipv4_config option
(** [ipv4_config_of_lease pkt] checks whether [pkt] represents
 *  a valid IPv4 configuration (regardless of the time at which
 *  [pkt] was sent and the time given for its validity).  If [pkt]
 *  looks usable, [Some config] is returned representing the values
 *  therein.  For [pkt] representing anything other than a complete
 *  lease containing the minimum information needed for an
 *  IPv4 configuration, [ipv4_config_of_lease pkt] returns [None]. *)

module Make(Time : Mirage_types_lwt.TIME) (Network : Mirage_types_lwt.NETWORK) : sig
  type t = Mirage_protocols_lwt.ipv4_config Lwt_stream.t
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
