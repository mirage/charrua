#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "dhcharrua-client" @@ fun c ->
  Ok [ Pkg.mllib "lib/dhcharrua-client.mllib";
       Pkg.test  "lib_test/test_client";
  ]
