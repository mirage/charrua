type t
type buffer = Cstruct.t
(** we expect all serialization and deserialization to happen through Cstruct.t *)

val pp : Format.formatter -> t -> unit

val create : ?with_xid : Cstruct.uint32 -> ?requests : Dhcp_wire.option_code list -> Macaddr.t -> (t * buffer)
(** [create mac] returns a pair of [t, buffer].  [t] represents the current 
 * state of the client in the lease transaction, and [buffer] is the suggested
 * next packet the caller should take to progress toward accepting a lease.
 * The optional argument [with_xid] allows the caller to specify a transaction ID
 * to use for the lease attempt.
 * [requests] is a list of option codes which the client should ask for in its
 * attempt to get a DHCP lease.  If [requests] is not given, we'll make an educated
 * guess rather than requesting nothing.
 *)

val input : t -> buffer -> [`Response of (t * buffer) | `New_lease of (t * Dhcp_wire.pkt) | `Noop ]
(** [input t buf] attempts to advance the state of [t]
 * with the contents of [buf].  If [buf] is invalid or not useful given
 * the current state of [t], [`Noop] is returned indicating no action should be taken.
 * Otherwise, either a [`Response] will be suggested along with a [t] whose state has been advanced,
 * or a [`New_lease] will be returned along with a [t] whose state has been advanced. *)

val lease : t -> Dhcp_wire.pkt option
(** [lease t] will return [Some lease] if [t] has succeeded in
 * completing a lease transaction with some server.
 * Note that the library has no sense of the passage of time, so expiration
 * is not considered; there is no guarantee that [Some lease] is still
 * valid on the network.  The caller is responsible for keeping track of
 * the time at which the lease was obtained, and renewing the lease when
 * necessary.
 * If [t] hasn't yet completed a lease transaction, [None] will be returned. *)

val renew : t -> [`Response of (t * buffer) | `Noop]
(** [renew t] returns either a [`Response] with the next state and suggested action
 * of the client attempting to renew [t]'s lease,
 * or [`Noop] if [t] does not have a lease and therefore can't be renewed. *)
