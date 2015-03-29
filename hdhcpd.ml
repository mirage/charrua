let hdhcpd debug verbose = `Ok

(* Parse command line and start the ball *)
open Cmdliner
let cmd =
  let debug = Arg.(value & flag & info ["d" ; "debug"]
                       ~doc:"Don't daemonize and be uber-verbose.") in
  let verbose = Arg.(value & flag & info ["v" ; "verbose"]
                       ~doc:"Verbose output.") in
  Term.(pure hdhcpd $ debug $ verbose),
  Term.info "hdhcpd" ~version:"0.1" ~doc:"Haesbaert DHCP"
let () = match Term.eval cmd with `Error _ -> exit 1 | _ -> exit 0
