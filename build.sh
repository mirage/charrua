#!/bin/sh

ocamlbuild -use-ocamlfind hdhcpd.native $@
ocamlbuild -use-ocamlfind pcap.native $@
