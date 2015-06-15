# hdhcp (WIP)

Hdhcp is an _ISC-licensed_ dhcpd implementation in ocaml, it supports a stripped-down ISC dhcpd.conf configuration.
This is a _work-in-progress_ software, and I'm learning more of ocaml as I write it.
Currently I can parse the configuration and interpret a full dhcp packet. It also does privilege separation and drops privileges so that we don't shoot ourselves in the foot.
After the basic functionality is in place, I intend to make this compatible with mirage-os.
