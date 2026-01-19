(** SMTP Lexer - RFC 5321 Command Tokenization *)

{
open Smtp_grammar

exception Lexer_error of string
}

let whitespace = [' ' '\t']+
let crlf = "\r\n"
let digit = ['0'-'9']
let alpha = ['a'-'z' 'A'-'Z']
let alphanum = ['a'-'z' 'A'-'Z' '0'-'9']

(* Characters allowed in local part (simplified)
   Note: '=' is excluded to allow proper parsing of ESMTP parameters like SIZE=1234 *)
let local_char = ['a'-'z' 'A'-'Z' '0'-'9' '!' '#' '$' '%' '&' '\'' '*' '+' '-' '/' '?' '^' '_' '`' '{' '|' '}' '~' '.']

(* Characters allowed in domain labels *)
let domain_char = ['a'-'z' 'A'-'Z' '0'-'9' '-']

(* For AUTH initial response - base64 characters *)
let base64_char = ['a'-'z' 'A'-'Z' '0'-'9' '+' '/' '=']

rule token = parse
  (* Whitespace - significant in some contexts *)
  | whitespace      { SP }

  (* Line ending *)
  | crlf            { CRLF }
  | eof             { EOF }

  (* SMTP Commands - case insensitive *)
  | "EHLO" | "ehlo" | "Ehlo"     { EHLO }
  | "HELO" | "helo" | "Helo"     { HELO }
  | "MAIL" | "mail" | "Mail"     { MAIL }
  | "RCPT" | "rcpt" | "Rcpt"     { RCPT }
  | "DATA" | "data" | "Data"     { DATA }
  | "RSET" | "rset" | "Rset"     { RSET }
  | "VRFY" | "vrfy" | "Vrfy"     { VRFY }
  | "EXPN" | "expn" | "Expn"     { EXPN }
  | "HELP" | "help" | "Help"     { HELP }
  | "NOOP" | "noop" | "Noop"     { NOOP }
  | "QUIT" | "quit" | "Quit"     { QUIT }
  | "STARTTLS" | "starttls" | "Starttls" | "StartTLS" | "STARTTLS" { STARTTLS }
  | "AUTH" | "auth" | "Auth"     { AUTH }

  (* Keywords in MAIL/RCPT commands - case insensitive *)
  | "FROM" | "from" | "From"     { FROM }
  | "TO" | "to" | "To"           { TO }

  (* Parameters - case insensitive *)
  | "SIZE" | "size" | "Size"           { SIZE }
  | "BODY" | "body" | "Body"           { BODY }
  | "7BIT" | "7bit" | "7Bit"           { SEVENBIT }
  | "8BITMIME" | "8bitmime" | "8BitMime" | "8BITMIME" { EIGHTBITMIME }
  | "BINARYMIME" | "binarymime"        { BINARYMIME }

  (* AUTH mechanisms - case insensitive *)
  | "PLAIN" | "plain" | "Plain"        { PLAIN }
  | "LOGIN" | "login" | "Login"        { LOGIN }

  (* Punctuation *)
  | ':'             { COLON }
  | '<'             { LANGLE }
  | '>'             { RANGLE }
  | '@'             { AT }
  | '='             { EQUALS }

  (* Null sender indicator *)
  | "<>"            { NULL_SENDER }

  (* Numbers for SIZE parameter *)
  | digit+ as n     { NUMBER (Int64.of_string n) }

  (* Domain - sequence of labels separated by dots *)
  | (domain_char+ ('.' domain_char+)*) as s { DOMAIN s }

  (* Local part of email - simplified *)
  | (local_char+) as s { LOCAL_PART s }

  (* Base64 for AUTH *)
  | (base64_char+) as s { BASE64 s }

  (* Catch-all for text arguments (VRFY, EXPN, HELP, NOOP) - excludes SMTP punctuation *)
  | [^ ' ' '\t' '\r' '\n' '<' '>' ':' '@' '=']+ as s { TEXT s }

  (* Error *)
  | _ as c          { raise (Lexer_error (Printf.sprintf "Unexpected character: %c" c)) }

(* Read remaining text on line until CRLF *)
and read_text acc = parse
  | crlf            { (String.concat "" (List.rev acc), true) }
  | eof             { (String.concat "" (List.rev acc), false) }
  | _ as c          { read_text (String.make 1 c :: acc) lexbuf }
