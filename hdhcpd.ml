open Lwt

let config_log = function
  | "debug" -> Lwt_log.add_rule "*" Lwt_log.Debug
  | "info" -> Lwt_log.add_rule "*" Lwt_log.Info
  | "notice" -> Lwt_log.add_rule "*" Lwt_log.Notice
  | _ -> invalid_arg "Verbosity should be debug|info|notice"

let hdhcpd verbosity =
  let () = config_log verbosity in
  let () = Lwt_log.ign_notice "Haesbaert DHCPD started" in
  Lwt_main.run (Lwt_log.notice "Haesbaert DHCPD finished")

(* Parse command line and start the ball *)
open Cmdliner
let cmd =
  let verbosity = Arg.(value & opt string "notice" & info ["v" ; "verbosity"]
                         ~doc:"Log verbosity, debug|info|notice") in
  Term.(pure hdhcpd $ verbosity),
  Term.info "hdhcpd" ~version:"0.1" ~doc:"Haesbaert DHCP"
let () = match Term.eval cmd with `Error _ -> exit 1 | _ -> exit 0
