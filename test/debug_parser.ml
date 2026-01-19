open Smtp_parser

let () =
  let test s =
    Printf.printf "Parsing: %S\n" s;
    match parse_command s with
    | Ok cmd -> Printf.printf "  OK: %s\n" (command_to_string cmd)
    | Error e -> Printf.printf "  Error: %s\n" e
  in
  (* Basic commands *)
  test "EHLO example.com\r\n";
  test "HELO example.com\r\n";
  test "MAIL FROM:<user@example.com>\r\n";
  test "MAIL FROM:<>\r\n";
  test "RCPT TO:<recipient@example.org>\r\n";
  test "DATA\r\n";
  test "QUIT\r\n";

  (* MAIL FROM with ESMTP parameters - these must work! *)
  test "MAIL FROM:<user@example.com> SIZE=1234\r\n";
  test "MAIL FROM:<user@example.com> SIZE=1234 BODY=8BITMIME\r\n";
  test "MAIL FROM:<user@example.com> SIZE=1234 BODY=7BIT\r\n";
  test "MAIL FROM:<user@example.com> BODY=8BITMIME\r\n";

  (* Unknown parameters - should be accepted and ignored *)
  test "MAIL FROM:<user@example.com> SMTPUTF8\r\n";
  test "MAIL FROM:<user@example.com> AUTH=<>\r\n";

  (* AUTH commands - test base64 with padding *)
  test "AUTH PLAIN\r\n";
  test "AUTH PLAIN dGVzdA\r\n";
  test "AUTH PLAIN dGVzdA=\r\n";
  test "AUTH PLAIN dGVzdA==\r\n";
  test "AUTH LOGIN\r\n"
