(** SMTP Grammar - RFC 5321 Command Parsing *)

%{
open Smtp_types
%}

(* Commands *)
%token EHLO HELO MAIL RCPT DATA RSET VRFY EXPN HELP NOOP QUIT STARTTLS AUTH

(* Keywords *)
%token FROM TO

(* Parameters *)
%token SIZE BODY SEVENBIT EIGHTBITMIME BINARYMIME
%token PLAIN LOGIN

(* Punctuation *)
%token COLON LANGLE RANGLE AT EQUALS SP CRLF EOF

(* Special *)
%token NULL_SENDER

(* Values *)
%token <string> DOMAIN LOCAL_PART TEXT BASE64
%token <int64> NUMBER

(* Entry point *)
%start <Smtp_types.smtp_command option> command

%%

command:
  | c = smtp_command CRLF   { Some c }
  | c = smtp_command EOF    { Some c }
  | CRLF                    { None }
  | EOF                     { None }
  ;

smtp_command:
  | EHLO SP d = domain_or_text       { Ehlo d }
  | HELO SP d = domain_or_text       { Helo d }
  | MAIL SP FROM COLON rp = reverse_path ps = mail_params
                                     { Mail_from { reverse_path = rp; params = ps } }
  | RCPT SP TO COLON fp = forward_path ps = rcpt_params
                                     { Rcpt_to { forward_path = fp; params = ps } }
  | DATA                             { Data }
  | RSET                             { Rset }
  | VRFY SP t = text_arg             { Vrfy t }
  | EXPN SP t = text_arg             { Expn t }
  | HELP                             { Help None }
  | HELP SP t = text_arg             { Help (Some t) }
  | NOOP                             { Noop None }
  | NOOP SP t = text_arg             { Noop (Some t) }
  | QUIT                             { Quit }
  | STARTTLS                         { Starttls }
  | AUTH SP m = auth_mechanism       { Auth { mechanism = m; initial_response = None } }
  | AUTH SP m = auth_mechanism SP ir = base64_value
                                     { Auth { mechanism = m; initial_response = Some ir } }
  ;

domain_or_text:
  | d = DOMAIN      { d }
  | t = TEXT        { t }
  | lp = LOCAL_PART { lp }  (* Sometimes domains look like local parts *)
  ;

reverse_path:
  | NULL_SENDER                         { None }
  | LANGLE RANGLE                       { None }
  | LANGLE lp = local_part AT d = domain RANGLE
                                        { Some { local_part = lp; domain = d } }
  ;

forward_path:
  | LANGLE lp = local_part AT d = domain RANGLE
                                        { { local_part = lp; domain = d } }
  ;

local_part:
  | lp = LOCAL_PART     { lp }
  | d = DOMAIN          { d }  (* Domain chars are subset of local-part chars *)
  | t = TEXT            { t }
  ;

domain:
  | d = DOMAIN          { d }
  | t = TEXT            { t }  (* Fallback *)
  ;

mail_params:
  | (* empty *)                     { [] }
  | SP p = mail_param ps = mail_params { p :: ps }
  ;

mail_param:
  | SIZE EQUALS n = NUMBER          { Size n }
  | BODY EQUALS SEVENBIT            { Body `SevenBit }
  | BODY EQUALS EIGHTBITMIME        { Body `EightBitMime }
  | BODY EQUALS BINARYMIME          { Body `BinaryMime }
  (* Accept unknown parameters - common ones from Postfix/other MTAs *)
  | AUTH EQUALS param_value         { Unknown_param ("AUTH", None) }
  | DOMAIN EQUALS param_value       { Unknown_param ("", None) }  (* Catch generic KEY=VALUE *)
  | TEXT EQUALS param_value         { Unknown_param ("", None) }
  | DOMAIN                          { Unknown_param ("", None) }  (* Catch FLAGS like SMTPUTF8 *)
  | TEXT                            { Unknown_param ("", None) }
  ;

param_value:
  | NULL_SENDER                     { () }
  | LANGLE RANGLE                   { () }
  | LANGLE lp = local_part AT d = domain RANGLE { ignore (lp, d) }
  | DOMAIN                          { () }
  | TEXT                            { () }
  | LOCAL_PART                      { () }
  | NUMBER                          { () }
  ;

rcpt_params:
  | (* empty *)                     { [] }
  (* RCPT TO params could be added here for NOTIFY, ORCPT *)
  ;

auth_mechanism:
  | PLAIN       { "PLAIN" }
  | LOGIN       { "LOGIN" }
  | t = TEXT    { String.uppercase_ascii t }
  | d = DOMAIN  { String.uppercase_ascii d }
  ;

base64_value:
  | b = BASE64      { b }
  | t = TEXT        { t }
  | d = DOMAIN      { d }
  | lp = LOCAL_PART { lp }
  | EQUALS          { "=" }  (* Single = is valid base64 padding *)
  ;

text_arg:
  | t = TEXT        { t }
  | d = DOMAIN      { d }
  | lp = LOCAL_PART { lp }
  | n = NUMBER      { Int64.to_string n }
  ;
