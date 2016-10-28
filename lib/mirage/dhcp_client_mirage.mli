val ipv4_config_of_lease : Dhcp_wire.pkt -> V1_LWT.ipv4_config option

module Make(Time : V1_LWT.TIME) (Network : V1_LWT.NETWORK) : sig
  val connect : ?requests:Dhcp_wire.option_code list
    -> Network.t -> V1_LWT.ipv4_config Lwt.t
end
