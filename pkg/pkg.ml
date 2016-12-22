#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let mirage = Conf.with_pkg "mirage-types-lwt"

let () =
  Pkg.describe "charrua-client" @@ fun c ->
  let mirage = Conf.value c mirage in
  Ok [ Pkg.mllib "src/charrua-client.mllib";
       Pkg.test  "test/test_client";
       Pkg.mllib ~cond:mirage "src/mirage/charrua-client-mirage.mllib";
  ]
