exception Error of string

type subnet = {
  network : Ipaddr.V4.Prefix.t;
  range : Ipaddr.V4.t * Ipaddr.V4.t;
  options : Dhcp.dhcp_option list;
}

type t = {
  subnets : subnet list;
  options : Dhcp.dhcp_option list;
}
