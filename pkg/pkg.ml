#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  let opams =
    [ Pkg.opam_file "opam" ~lint_deps_excluding:(Some ["ppx_tools" ; "ppx_sexp_conv" ; "menhir"]) ]
  in
  Pkg.describe ~opams "charrua-core" @@ fun _ ->
  Ok [
    Pkg.mllib ~api:["Dhcp_wire"] "lib/dhcp_wire.mllib";
    Pkg.mllib ~api:["Dhcp_server"] "lib/dhcp_server.mllib";
    Pkg.test "test/test"
  ]
