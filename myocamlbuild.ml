open Ocamlbuild_plugin ;;
dispatch begin function
  | After_rules ->
    pflag ["ocaml";"compile";] "ppopt" (fun s -> S [A"-ppopt"; A s]);
    pflag ["ocaml";"ocamldep";] "ppopt" (fun s -> S [A"-ppopt"; A s])
  | _ -> ()
end;;
