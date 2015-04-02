(** Simple log framework since I didn't any other **)

type level = Notice | Info | Debug
(** All valid verbosity levels **)

val current_level : level ref
(** Current verbosity level, might be changed any time **)

val str_of_level : level -> string
(** Conver level to string **)

val level_of_str : string -> level
(** Convert string to level, raising invalid_arg if string is invalid **)

val notice : ('a, out_channel, unit) format -> 'a
(** Normal, high priority logging, always on **)

val warn : ('a, out_channel, unit) format -> 'a
(** Like notice, but prepend "warning: " **)

val info : ('a, out_channel, unit) format -> 'a
(** Print if level is >= Info **)

val debug : ('a, out_channel, unit) format -> 'a
(** Print if level is >= Debug **)

(** Lwt variants, same as above, but return unit Lwt.t
    Useful for using with Lwt.bind and friends **)
val notice_lwt : ('a, out_channel, unit, unit, unit, unit Lwt.t) format6 -> 'a
val warn_lwt : ('a, out_channel, unit, unit, unit, unit Lwt.t) format6 -> 'a
val info_lwt : ('a, out_channel, unit, unit, unit, unit Lwt.t) format6 -> 'a
val debug_lwt : ('a, out_channel, unit, unit, unit, unit Lwt.t) format6 -> 'a
