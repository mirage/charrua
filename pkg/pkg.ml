#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let mirage = Conf.with_pkg "mirage-types-lwt"

let () =
  Pkg.describe "dhcharrua-client" @@ fun c ->
  let mirage = Conf.value c mirage in
  Ok [ Pkg.mllib "lib/dhcharrua-client.mllib";
       Pkg.test  "lib_test/test_client";
       Pkg.mllib ~cond:mirage "lib/mirage/dhcharrua-client-mirage.mllib";
  ]
