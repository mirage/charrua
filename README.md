# hdhcp

Hdhcp is an _ISC-licensed_ dhcpd implementation in ocaml, it supports a
stripped-down ISC dhcpd.conf configuration.  This is project was an excuse to
learn more of ocaml.

Basic functionality is in place, it should be able to work with multiple
interfaces in a simple environment, currently only a few options can be
advertised.

Work can now begin on adapting it to Mirage to run it as a unikernel.
