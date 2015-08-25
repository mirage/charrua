exception Syntax_error of string

let choke lexbuf s =
  let open Lexing in
  let pos = lexbuf.lex_curr_p in
  let str = Printf.sprintf "%s at line %d around `%s`"
      s pos.pos_lnum (Lexing.lexeme lexbuf)
  in
  raise (Syntax_error str)

let parse configtxt interfaces =
  let lex = Lexing.from_string configtxt in
  try
    Config.config_of_ast (Parser.main Lexer.lex lex) interfaces
  with
  | Parser.Error -> choke lex "Parser error"
  | Lexer.Error e -> raise (Syntax_error e)
  | Config.Error e -> choke lex e
