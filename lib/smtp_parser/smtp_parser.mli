(** SMTP Parser - RFC 5321 Command Parsing and Response Serialization *)

open Smtp_types

(** {1 Command Parsing} *)

(** Parse an SMTP command line.

    @param line The command line (with or without trailing CRLF)
    @return Ok command on success, Error message on parse failure *)
val parse_command : string -> (smtp_command, string) result

(** {1 DATA Mode Parsing} *)

(** Read message data from a line reader function.

    Reads until a line containing only "." is received.
    Performs dot-unstuffing per RFC 5321 Section 4.5.2.

    @param read_line Function that returns next line or None at EOF
    @return Ok data on success, Error on failure *)
val parse_data : read_line:(unit -> string option) -> (string, string) result

(** {1 AUTH Decoding} *)

(** Decode SASL PLAIN authentication (RFC 4616).

    @param data Base64-encoded PLAIN data
    @return Some (authzid option, authcid, password) on success *)
val decode_auth_plain : string -> (string option * string * string) option

(** Decode base64 string.

    @param data Base64-encoded string
    @return Some decoded on success *)
val decode_base64 : string -> string option

(** Encode string to base64. *)
val encode_base64 : string -> string

(** {1 Response Serialization} *)

(** Serialize an SMTP response to a Faraday buffer. *)
val serialize_response : Faraday.t -> smtp_response -> unit

(** Convert response to string. *)
val response_to_string : smtp_response -> string

(** {1 Command String Conversion} *)

(** Convert command to string representation (for logging). *)
val command_to_string : smtp_command -> string
