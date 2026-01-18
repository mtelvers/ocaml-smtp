(** SMTP Parser - RFC 5321 Command Parsing and Response Serialization

    Provides parsing for SMTP commands and serialization for responses.

    Command examples:
    - EHLO mail.example.com
    - MAIL FROM:<user@example.com> SIZE=1024
    - RCPT TO:<recipient@example.org>
    - DATA
    - AUTH PLAIN dXNlcm5hbWUAcGFzc3dvcmQ= *)

open Smtp_types

(** {1 Command Parsing} *)

(** Parse an SMTP command line.

    @param line The command line (with or without trailing CRLF)
    @return Ok command on success, Error message on parse failure *)
let parse_command line =
  (* Strip trailing CRLF if present *)
  let line =
    let len = String.length line in
    if len >= 2 && String.sub line (len - 2) 2 = "\r\n" then
      String.sub line 0 (len - 2)
    else if len >= 1 && line.[len - 1] = '\n' then
      String.sub line 0 (len - 1)
    else
      line
  in
  (* Check line length limit - RFC 5321 Section 4.5.3.1.4 *)
  if String.length line > max_command_line_length then
    Error "Line too long"
  else
    let lexbuf = Lexing.from_string (line ^ "\r\n") in
    try
      match Smtp_grammar.command Smtp_lexer.token lexbuf with
      | Some cmd -> Ok cmd
      | None -> Error "Empty command"
    with
    | Smtp_lexer.Lexer_error msg -> Error ("Lexer error: " ^ msg)
    | Smtp_grammar.Error -> Error "Parse error"

(** {1 DATA Mode Parsing}

    In DATA mode, the message body is read until a line containing only "."
    is received. Lines starting with "." have the leading dot removed
    (dot-unstuffing per RFC 5321 Section 4.5.2). *)

(** Read message data from a line reader function.

    @param read_line Function that returns next line or None at EOF
    @return Ok data on success (dot removed, unstuffed), Error on failure *)
let parse_data ~read_line =
  let buf = Buffer.create 4096 in
  let rec loop () =
    match read_line () with
    | None -> Error "Connection closed during DATA"
    | Some line ->
      (* Check for terminating line - single dot *)
      let stripped =
        let len = String.length line in
        if len >= 2 && String.sub line (len - 2) 2 = "\r\n" then
          String.sub line 0 (len - 2)
        else if len >= 1 && line.[len - 1] = '\n' then
          String.sub line 0 (len - 1)
        else
          line
      in
      if stripped = "." then
        Ok (Buffer.contents buf)
      else begin
        (* Dot-unstuffing: remove leading dot if line starts with ".." *)
        let unstuffed =
          if String.length stripped >= 2 && stripped.[0] = '.' && stripped.[1] = '.' then
            String.sub stripped 1 (String.length stripped - 1)
          else if String.length stripped >= 1 && stripped.[0] = '.' then
            (* Single dot that's not the terminator - shouldn't happen with proper stuffing,
               but handle it gracefully *)
            String.sub stripped 1 (String.length stripped - 1)
          else
            stripped
        in
        Buffer.add_string buf unstuffed;
        Buffer.add_string buf "\r\n";
        loop ()
      end
  in
  loop ()

(** {1 AUTH Decoding}

    SASL PLAIN mechanism (RFC 4616): base64([authzid] NUL authcid NUL password)
    SASL LOGIN mechanism: base64(username) then base64(password) *)

(** Decode SASL PLAIN authentication.

    @param data Base64-encoded PLAIN data
    @return Some (authzid, authcid, password) on success, None on failure *)
let decode_auth_plain data =
  match Base64.decode data with
  | Error _ -> None
  | Ok decoded ->
    (* Format: [authzid] NUL authcid NUL password *)
    let parts = String.split_on_char '\x00' decoded in
    match parts with
    | [authzid; authcid; password] ->
      let authzid = if authzid = "" then None else Some authzid in
      Some (authzid, authcid, password)
    | [authcid; password] ->
      (* No authzid provided *)
      Some (None, authcid, password)
    | _ -> None

(** Decode base64 for LOGIN mechanism step.

    @param data Base64-encoded string
    @return Some decoded on success, None on failure *)
let decode_base64 data =
  match Base64.decode data with
  | Ok s -> Some s
  | Error _ -> None

(** Encode string to base64 for AUTH challenges. *)
let encode_base64 data =
  Base64.encode_string data

(** {1 Response Serialization} *)

(** Serialize an SMTP response to a Faraday buffer.

    Multi-line responses use the format:
    - code-text CRLF (for all but last line, hyphen separator)
    - code SP text CRLF (for last line, space separator)

    Enhanced status codes (RFC 3463) are prepended to the text. *)
let serialize_response faraday response =
  let { code; enhanced_code; lines } = response in
  let code_str = string_of_int code in
  let enhanced_prefix = match enhanced_code with
    | None -> ""
    | Some (c, s, d) -> Printf.sprintf "%d.%d.%d " c s d
  in
  match lines with
  | [] ->
    (* Empty response - just code *)
    Faraday.write_string faraday code_str;
    Faraday.write_string faraday " ";
    Faraday.write_string faraday enhanced_prefix;
    Faraday.write_string faraday "OK";
    Faraday.write_string faraday "\r\n"
  | [line] ->
    (* Single line response *)
    Faraday.write_string faraday code_str;
    Faraday.write_string faraday " ";
    Faraday.write_string faraday enhanced_prefix;
    Faraday.write_string faraday line;
    Faraday.write_string faraday "\r\n"
  | first :: rest ->
    (* Multi-line response - first line and middle lines use hyphen *)
    Faraday.write_string faraday code_str;
    Faraday.write_string faraday "-";
    Faraday.write_string faraday enhanced_prefix;
    Faraday.write_string faraday first;
    Faraday.write_string faraday "\r\n";
    let rec write_rest = function
      | [] -> ()
      | [last] ->
        (* Last line uses space *)
        Faraday.write_string faraday code_str;
        Faraday.write_string faraday " ";
        Faraday.write_string faraday last;
        Faraday.write_string faraday "\r\n"
      | line :: more ->
        Faraday.write_string faraday code_str;
        Faraday.write_string faraday "-";
        Faraday.write_string faraday line;
        Faraday.write_string faraday "\r\n";
        write_rest more
    in
    write_rest rest

(** Convert response to string. *)
let response_to_string response =
  let faraday = Faraday.create 256 in
  serialize_response faraday response;
  Faraday.serialize_to_string faraday

(** {1 Command String Conversion (for debugging/logging)} *)

(** Convert command to string representation. *)
let command_to_string = function
  | Ehlo domain -> "EHLO " ^ domain
  | Helo domain -> "HELO " ^ domain
  | Mail_from { reverse_path; params = _ } ->
    "MAIL FROM:" ^ reverse_path_to_string reverse_path
  | Rcpt_to { forward_path; params = _ } ->
    "RCPT TO:" ^ forward_path_to_string forward_path
  | Data -> "DATA"
  | Rset -> "RSET"
  | Vrfy s -> "VRFY " ^ s
  | Expn s -> "EXPN " ^ s
  | Help None -> "HELP"
  | Help (Some s) -> "HELP " ^ s
  | Noop None -> "NOOP"
  | Noop (Some s) -> "NOOP " ^ s
  | Quit -> "QUIT"
  | Starttls -> "STARTTLS"
  | Auth { mechanism; initial_response = None } -> "AUTH " ^ mechanism
  | Auth { mechanism; initial_response = Some _ } -> "AUTH " ^ mechanism ^ " [data]"
