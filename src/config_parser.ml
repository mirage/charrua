exception Syntax_error of string

let choke lexbuf s =
  let open Lexing in
  let pos = lexbuf.lex_curr_p in
  let str = Printf.sprintf "%s at line %d around `%s`"
      s pos.pos_lnum (Lexing.lexeme lexbuf)
  in
  raise (Syntax_error str)

let parse ?(path="-") interfaces =
  let ic = if path = "-" then stdin else open_in path in
  let lex = Lexing.from_channel ic in
  Util.finalize (fun () ->
      try
        Config.config_of_ast (Parser.main Lexer.lex lex) interfaces
      with
      | Parser.Error -> choke lex "Parser error"
      | Lexer.Error e -> raise (Syntax_error e)
      | Config.Error e -> choke lex e)
    (fun () -> if ic <> stdin then close_in ic)
