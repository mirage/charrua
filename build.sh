#!/bin/sh

ocamlbuild \
	-use-ocamlfind \
	-pkg cmdliner \
	-tag debug \
	-tag bin_annot \
	-cflags "-w A-4-33-40-41-42-43-34-44" \
	-cflags -strict-sequence \
	hdhcpd.byte
