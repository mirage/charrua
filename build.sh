#!/bin/sh

for t in hdhcpd.native pcap.native config_parser.native; do
	echo Building $t...
	ocamlbuild -use-ocamlfind $t $@
done
