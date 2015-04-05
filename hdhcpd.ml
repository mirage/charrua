open Lwt

let () = Printexc.record_backtrace true

let config_log verbosity =
  Log.current_level := Log.level_of_str verbosity

let open_dhcp_sock () =
  let open Lwt_unix in
  let sock = socket PF_INET SOCK_DGRAM 0 in
  let () = setsockopt sock SO_REUSEADDR true in
  let () = setsockopt sock SO_BROADCAST true in
  let () = bind sock (ADDR_INET (Unix.inet_addr_any, 67)) in
  sock

let valid_pkt pkt =
  let open Dhcp in
  if pkt.op <> Bootrequest then
    false
  else if pkt.htype <> Ethernet_10mb then
    false
  else if pkt.hlen <> 6 then
    false
  else if pkt.hops <> 0 then
    false
  else
    true

let input_pkt pkt =
  let open Dhcp in
  let drop = () in
  if not (valid_pkt pkt) then begin
    Log.warn "Invalid pkt, dropping";
    drop;
  end;
  Printf.printf "%s\n%!" (str_of_pkt pkt)

let rec dhcp_recv sock =
  let buffer = Dhcp.make_buf () in
  lwt n = Lwt_cstruct.read sock buffer in
  Log.debug "dhcp sock read %d bytes" n;
  if n = 0 then
    failwith "Unexpected EOF in DHCPD socket";
  if n >= Dhcp.pkt_min_len then
    input_pkt (Dhcp.pkt_of_buf buffer n)
  else
    Log.warn "pkt too small (%d), dropping" n;
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
