%{
  type statement =
    | Range of Ipaddr.V4.t * Ipaddr.V4.t
    | Dhcp_option of Dhcp.dhcp_option
    | Hw_eth of string
    | Fixed_addr of Ipaddr.V4.t

  let choke s =
    raise (Config.Error s)
%}

%token <Ipaddr.V4.t> IP
%token <string> MACADDR
%token <string> STRING
%token DOMAINNAME
%token DOMAINNAMESERVERS
%token EOF
%token ETHERNET
%token FIXEDADDRESS
%token HARDWARE
%token HOST
%token LBRACKET
%token NETMASK
%token OPTION
%token RANGE
%token RBRACKET
%token ROUTERS
%token SCOLON
%token SUBNET
%token WORD

%start <Config.t> main
%%

main:
| s = statement; ss = statements; sub = subnet; subs = subnets; EOF {
  let statements = s :: ss in
  let subnets = sub :: subs in
  (* Now extract the options from the statements *)
  let options = List.map (function
      | Dhcp_option o -> o
      | _ -> choke "Only dhcp options in the global section")
      statements
  in
  Config.{ subnets; options }
}

statements:
  | (* empty *) { [] }
  | s = statement; ss = statements { s :: (List.rev ss) }

statement:
  | OPTION; DOMAINNAME; v = STRING; SCOLON { Dhcp_option (Dhcp.Domain_name v)}
  | OPTION; DOMAINNAMESERVERS; v = IP; SCOLON { Dhcp_option (Dhcp.Dns_servers [v]) }
  | OPTION; ROUTERS; v = IP; SCOLON { Dhcp_option (Dhcp.Routers [v]) }
  | RANGE; v1 = IP; v2 = IP; SCOLON { Range (v1, v2) }
  | HARDWARE; ETHERNET; mac = MACADDR; SCOLON { Hw_eth mac }
  | FIXEDADDRESS; v = IP; SCOLON { Fixed_addr v }

subnets:
  | (* empty *) { [] }
  | sub = subnet; subs = subnets { sub :: (List.rev subs) }

subnet:
| SUBNET; ip = IP; NETMASK; mask = IP; LBRACKET; ss = statements; hosts; RBRACKET {
  let statements = ss in
  let network = Ipaddr.V4.Prefix.of_netmask mask ip in
  (* First find the range statement, XXX ignoring if multiple *)
  let rangest = try
      List.find (function
          | Range _ -> true
          | _ -> false)
        statements
    with Not_found ->
      choke ("Missing `range` statement for subnet " ^ (Ipaddr.V4.to_string ip))
  in
  (* Now extract the tuple within the Range *)
  let range = match rangest with
    | Range (v1, v2) -> (v1, v2)
    | _ -> choke "Internal error 1, report this with the config file"
  in
  (* Extract the dhcp options statements *)
  let optionsst = List.filter (function
      | Dhcp_option _ -> true
      | _ -> false)
      statements
  in
  (* Now extract the options from the statements *)
  let options = List.map (function
      | Dhcp_option o -> o
      | _ -> choke "Internal error 2, report this with the config file")
      optionsst
  in
  Config.{ network; range; options }
}

hosts:
  | (* empty *) { }
  | host; hosts { }

host:
  | HOST; WORD; LBRACKET; statements; RBRACKET { }
