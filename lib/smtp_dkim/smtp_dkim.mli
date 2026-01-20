(** DKIM Verification and Signing - RFC 6376

    DomainKeys Identified Mail signature verification and signing to confirm
    that an email was authorized by the domain owner. *)

(** {1 Types} *)

(** DKIM signature algorithm *)
type algorithm =
  | Rsa_sha256
  | Rsa_sha1

(** Canonicalization method *)
type canonicalization = Simple | Relaxed

(** {1 Canonicalization} *)

(** Canonicalize message body according to RFC 6376.
    @param canon Canonicalization method (Simple or Relaxed)
    @param body The message body
    @return Canonicalized body *)
val canonicalize_body : canonicalization -> string -> string

(** Compute body hash.
    @param algorithm Hash algorithm (Rsa_sha256 or Rsa_sha1)
    @param body Canonicalized body
    @return Raw hash bytes *)
val compute_body_hash : algorithm -> string -> string

(** {1 Verification} *)

(** DKIM verification result *)
type dkim_result =
  | Dkim_pass of string       (** Verified, includes domain *)
  | Dkim_fail of string       (** Signature invalid *)
  | Dkim_temperror of string  (** Temporary error (DNS) *)
  | Dkim_permerror of string  (** Permanent error (syntax/key) *)
  | Dkim_none                 (** No signature present *)

(** Verify a DKIM signature.

    @param dns DNS resolver
    @param raw_headers Raw email headers (including DKIM-Signature)
    @param body Email body
    @return DKIM verification result *)
val verify :
  dns:Smtp_dns.t ->
  raw_headers:string ->
  body:string ->
  dkim_result

(** Convert DKIM result to string *)
val result_to_string : dkim_result -> string

(** Format DKIM result for Authentication-Results header *)
val format_auth_results : dkim_result -> string

(** {1 Signing} *)

(** DKIM signing configuration *)
type signing_config

(** Create a signing configuration.

    @param private_key_pem PEM-encoded RSA private key
    @param domain The signing domain (d= tag)
    @param selector The selector (s= tag), used for DNS lookup
    @param headers List of headers to sign (default: from, to, subject, date, message-id)
    @return Signing configuration or error message *)
val create_signing_config :
  private_key_pem:string ->
  domain:string ->
  selector:string ->
  ?headers:string list ->
  unit ->
  (signing_config, string) result

(** Load signing configuration from a private key file.

    @param key_file Path to PEM-encoded RSA private key file
    @param domain The signing domain (d= tag)
    @param selector The selector (s= tag)
    @param headers List of headers to sign
    @return Signing configuration or error message *)
val load_signing_config :
  key_file:string ->
  domain:string ->
  selector:string ->
  ?headers:string list ->
  unit ->
  (signing_config, string) result

(** Sign a message with DKIM.

    Generates a DKIM-Signature header for the message.

    @param config Signing configuration
    @param headers Raw message headers (without DKIM-Signature)
    @param body Message body
    @return The DKIM-Signature header line to prepend to the message *)
val sign :
  config:signing_config ->
  headers:string ->
  body:string ->
  (string, string) result

(** Sign a complete message and return the message with DKIM-Signature prepended.

    @param config Signing configuration
    @param message Complete message (headers + body)
    @return Message with DKIM-Signature header prepended *)
val sign_message :
  config:signing_config ->
  message:string ->
  (string, string) result
