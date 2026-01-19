(* Manually trace through what the lexer produces *)
let test_string = "MAIL FROM:<user@example.com> SIZE=1234\r\n"

let () =
  Printf.printf "Testing: %S\n" test_string;
  let lexbuf = Lexing.from_string test_string in
  let rec loop () =
    try
      let tok = Smtp_lexer.token lexbuf in
      let pos = lexbuf.Lexing.lex_curr_pos in
      let s = Lexing.lexeme lexbuf in
      Printf.printf "  Token at %d: %S\n" pos s;
      if tok <> Smtp_grammar.EOF && tok <> Smtp_grammar.CRLF then loop ()
    with e ->
      Printf.printf "  Exception: %s\n" (Printexc.to_string e)
  in
  loop ()
