let config_log verbosity =
  Log.current_level := Log.level_of_str verbosity

let hdhcpd verbosity =
  let () = config_log verbosity in
  let () = Log.notice "Haesbaert DHCPD started" in
  Lwt_main.run (Log.notice_lwt "Haesbaert DHCP finished")

(* Parse command line and start the ball *)
open Cmdliner
let cmd =
  let verbosity = Arg.(value & opt string "notice" & info ["v" ; "verbosity"]
                         ~doc:"Log verbosity, debug|info|notice") in
  Term.(pure hdhcpd $ verbosity),
  Term.info "hdhcpd" ~version:"0.1" ~doc:"Haesbaert DHCP"
let () = match Term.eval cmd with `Error _ -> exit 1 | _ -> exit 0
