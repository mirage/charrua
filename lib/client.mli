type t
type buffer = Cstruct.t
(** we expect all serialization and deserialization to happen through Cstruct.t *)

val pp : Format.formatter -> t -> unit

val create : mac:Macaddr.t -> (t * buffer)
(** [create ~mac] returns a pair of [t, buffer].  [t] represents the current 
 * state of the client in the lease transaction, and [buffer] is the suggested
 * next packet the caller should take to progress toward accepting a lease. *)

val renew : t -> (t * buffer) option
(** [renew t] attempts to begin a renewal tranaction.
 * If [t] has successfully bound a previous lease, [renew t] will return a new
 * [Some (state, action)] usable to begin the renewal process.
 * If [t] has not yet successfully bound a lease, [renew t] returns [None]. *)

val input : t -> buffer -> (t * buffer option)
(** [input t buf] attempts to advance the state of [t]
 * with the contents of [buf].  If [buf] is valid input to the
 * DHCP input parser and the information within is useful given the
 * current state of [t], the state will be advanced and a new [Some packet]
 * suggested for the caller to send.
 * If not, the previous [t] will be returned with [None]. *)

val lease : t -> Dhcp_wire.pkt option
(** [lease t] will return [Some lease] if [t] has succeeded in
 * completing a lease transaction with some server.
 * Note that the library has no sense of the passage of time, so expiration
 * is not considered; there is no guarantee that [Some lease] is still
 * valid on the network.  The caller is responsible for keeping track of
 * time time at which the lease was obtained, and renewing the lease when
 * necessary.
 * If [t] hasn't yet completed a lease transaction, [None] will be returned. *)
