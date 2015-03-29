open Lwt

let config_log verbosity =
  match verbosity with
  | None -> `Ok ()
  | Some verbosity ->
    let vlevel = match verbosity with
      | "debug" -> Some Lwt_log.Debug
      | "info" -> Some Lwt_log.Info
      | "notice" -> Some Lwt_log.Notice
      | _ -> None
    in match vlevel with
    | Some vlevel -> Lwt_log.Section.(set_level main vlevel);
      `Ok ()
    | None -> `Error (true, "invalid verbosity")

let hdhcpd verbosity =
  match (config_log verbosity) with
  | `Error (t, e) -> `Error (t, e)
  | _ -> Lwt_main.run(
      Lwt_log.notice "Haesbaert DHCPD started" >>= fun () ->
      Lwt_log.notice "Haesbaert DHCPD finished" >>= fun () ->
      Lwt.return (`Ok ()))

(* Parse command line and start the ball *)
open Cmdliner
let cmd =
  let verbosity = Arg.(value & opt (some string) None & info ["v" ; "verbosity"]
                         ~doc:"Log verbosity, debug|info|notice") in
  Term.(ret (pure hdhcpd $ verbosity)),
  Term.info "hdhcpd" ~version:"0.1" ~doc:"Haesbaert DHCP"
let () = match Term.eval cmd with `Error _ -> exit 1 | _ -> exit 0
