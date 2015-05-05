(*
 * Copyright (c) 2015 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

{
open Lexing
open Parser

exception Error of string

let choke lexbuf s =
  let open Lexing in
  let pos = lexbuf.lex_curr_p in
  let str = Printf.sprintf "%s at line %d around `%s`"
      s pos.pos_lnum (Lexing.lexeme lexbuf)
  in
  raise (Error str)

}
let white = [' ' '\t']+
let newline = '\r' | '\n' | "\r\n"
let comment = '#'+
(* A naive regex, we'll double check later with Ipaddr module *)
let ip = ['0' - '9']+ '.' ['0' - '9']+ '.' ['0' - '9']+ '.' ['0' - '9']+
(* No repetition in ocamllex :-( *)
let macaddr = ['a' - 'f' 'A' - 'F' '0' - '9'] ['a' - 'f' 'A' - 'F' '0' - '9'] ':'
    ['a' - 'f' 'A' - 'F' '0' - '9'] ['a' - 'f' 'A' - 'F' '0' - '9'] ':'
    ['a' - 'f' 'A' - 'F' '0' - '9'] ['a' - 'f' 'A' - 'F' '0' - '9'] ':'
    ['a' - 'f' 'A' - 'F' '0' - '9'] ['a' - 'f' 'A' - 'F' '0' - '9'] ':'
    ['a' - 'f' 'A' - 'F' '0' - '9'] ['a' - 'f' 'A' - 'F' '0' - '9'] ':'
    ['a' - 'f' 'A' - 'F' '0' - '9'] ['a' - 'f' 'A' - 'F' '0' - '9']
let word = ['a'-'z' 'A'-'Z' '0'-'9' '_' '-'] ['a'-'z' 'A'-'Z' '0'-'9' '_' '-']*

rule lex = parse
  | white { lex lexbuf }
  | newline  { new_line lexbuf; lex lexbuf }
  | ip as ip { IP(Ipaddr.V4.of_string_exn ip) }
  | macaddr as mac { MACADDR(Macaddr.of_string_exn mac) }
  | '"' { lex_string (Buffer.create 17) lexbuf }
  | ',' { COMMA }
  | ';' { SCOLON }
  | '{' { LBRACKET }
  | '}' { RBRACKET }
  | "domain-name" { DOMAINNAME }
  | "domain-name-servers" { DOMAINNAMESERVERS }
  | "ethernet" { ETHERNET }
  | "fixed-address" { FIXEDADDRESS }
  | "hardware" { HARDWARE }
  | "host" { HOST }
  | "netmask" { NETMASK }
  | "option" { OPTION }
  | "range" { RANGE }
  | "routers" { ROUTERS }
  | "subnet" { SUBNET }
  | comment { lex_comment lexbuf; lex lexbuf }
  | word as word { WORD(word) }
  | _ { choke lexbuf "Invalid syntax" }
  | eof { EOF }

and lex_comment = parse
  | eof     { () }
  | newline { new_line lexbuf }
  | _       { lex_comment lexbuf }

and lex_string buf = parse
  | '"'       { STRING (Buffer.contents buf) }
  | '\\' '/'  { Buffer.add_char buf '/'; lex_string buf lexbuf }
  | '\\' '\\' { Buffer.add_char buf '\\'; lex_string buf lexbuf }
  | '\\' 'b'  { Buffer.add_char buf '\b'; lex_string buf lexbuf }
  | '\\' 'f'  { Buffer.add_char buf '\012'; lex_string buf lexbuf }
  | '\\' 'n'  { Buffer.add_char buf '\n'; lex_string buf lexbuf }
  | '\\' 'r'  { Buffer.add_char buf '\r'; lex_string buf lexbuf }
  | '\\' 't'  { Buffer.add_char buf '\t'; lex_string buf lexbuf }
  | [^ '"' '\\']+
    { Buffer.add_string buf (Lexing.lexeme lexbuf);
      lex_string buf lexbuf
    }
  | _ { choke lexbuf "Illegal string character" }
  | eof { choke lexbuf "String is not terminated" }
