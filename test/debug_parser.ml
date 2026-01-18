open Smtp_parser

let () =
  let test s =
    Printf.printf "Parsing: %S\n" s;
    match parse_command s with
    | Ok cmd -> Printf.printf "  OK: %s\n" (command_to_string cmd)
    | Error e -> Printf.printf "  Error: %s\n" e
  in
  test "MAIL FROM:<user@example.com>\r\n";
  test "MAIL FROM:<>\r\n";
  test "RCPT TO:<recipient@example.org>\r\n"
