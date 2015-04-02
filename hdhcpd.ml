open Lwt

let () = Printexc.record_backtrace true

let config_log verbosity =
  Log.current_level := Log.level_of_str verbosity

let open_dhcp_sock () =
  let open Lwt_unix in
  let sock = socket PF_INET SOCK_DGRAM 0 in
  let () = setsockopt sock SO_REUSEADDR true in
  let () = bind sock (ADDR_INET (Unix.inet_addr_any, 67)) in
  sock

let rec dhcp_recv sock =
  let buffer_size = 2048 in
  let buffer = Bytes.create buffer_size in
  lwt n = Lwt_unix.read sock buffer 0 buffer_size in
  let () = Log.debug "dhcp sock read %d bytes" n in
  let () = if n = 0 then
      failwith "Unexpected EOF in DHCPD socket" in
  dhcp_recv sock

let hdhcpd verbosity =
  let () = config_log verbosity in
  let () = Log.notice "Haesbaert DHCPD started" in
  let sock = open_dhcp_sock () in
  let recv_thread = dhcp_recv sock in
  Lwt_main.run (recv_thread >>= fun () ->
    Log.notice_lwt "Haesbaert DHCP finished")

(* Parse command line and start the ball *)
open Cmdliner
let cmd =
  let verbosity = Arg.(value & opt string "notice" & info ["v" ; "verbosity"]
                         ~doc:"Log verbosity, debug|info|notice") in
  Term.(pure hdhcpd $ verbosity),
  Term.info "hdhcpd" ~version:"0.1" ~doc:"Haesbaert DHCP"
let () = match Term.eval cmd with `Error _ -> exit 1 | _ -> exit 0
