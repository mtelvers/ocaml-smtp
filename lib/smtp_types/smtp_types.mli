(** SMTP Types - RFC 5321 Core Types

    Implements types for {{:https://datatracker.ietf.org/doc/html/rfc5321}RFC 5321} SMTP protocol.

    Key security invariant: Closed relay enforcement - unauthenticated senders
    can only deliver to local domains. *)

(** {1 Email Address Types} *)

(** Local part of an email address (max 64 octets per RFC 5321 Section 4.5.3.1.1) *)
type local_part = string

(** Domain name (max 255 octets per RFC 5321 Section 4.5.3.1.2) *)
type domain = string

(** Complete email address *)
type email_address = {
  local_part : local_part;
  domain : domain;
}

(** Reverse-path (MAIL FROM sender). None represents null sender <> *)
type reverse_path = email_address option

(** Forward-path (RCPT TO recipient) *)
type forward_path = email_address

(** {1 SMTP Command Parameters} *)

(** MAIL FROM parameters - RFC 5321 Section 4.1.1.2 *)
type mail_param =
  | Size of int64                                    (** RFC 1870 SIZE extension *)
  | Body of [ `SevenBit | `EightBitMime | `BinaryMime ]  (** RFC 6152 8BITMIME *)
  | Auth_param of email_address option               (** RFC 4954 AUTH parameter *)

(** RCPT TO parameters - RFC 5321 Section 4.1.1.3 *)
type rcpt_param =
  | Notify of [ `Never | `Success | `Failure | `Delay ] list  (** DSN notifications *)
  | Orcpt of string                                          (** Original recipient *)

(** {1 SMTP Commands} *)

(** SMTP commands per RFC 5321 Section 4.1 *)
type smtp_command =
  | Ehlo of domain
  | Helo of domain
  | Mail_from of {
      reverse_path : reverse_path;
      params : mail_param list;
    }
  | Rcpt_to of {
      forward_path : forward_path;
      params : rcpt_param list;
    }
  | Data
  | Rset
  | Vrfy of string
  | Expn of string
  | Help of string option
  | Noop of string option
  | Quit
  | Starttls
  | Auth of {
      mechanism : string;
      initial_response : string option;
    }

(** {1 Connection State Machine} *)

(** Connection state per RFC 5321 Section 3 state machine *)
type connection_state =
  | Initial
  | Greeted of { client_domain : domain; tls_active : bool }
  | Authenticated of { username : string; client_domain : domain; tls_active : bool }
  | Mail_from_accepted of {
      username : string option;
      client_domain : domain;
      sender : reverse_path;
      params : mail_param list;
      tls_active : bool;
    }
  | Rcpt_to_accepted of {
      username : string option;
      client_domain : domain;
      sender : reverse_path;
      recipients : forward_path list;
      params : mail_param list;
      tls_active : bool;
    }
  | Data_mode of {
      username : string option;
      client_domain : domain;
      sender : reverse_path;
      recipients : forward_path list;
      tls_active : bool;
    }
  | Quit

(** {1 SMTP Responses} *)

(** Reply code per RFC 5321 Section 4.2 (range 200-599) *)
type reply_code = int

(** Enhanced status code per RFC 3463 (class.subject.detail) *)
type enhanced_code = int * int * int

(** SMTP response *)
type smtp_response = {
  code : reply_code;
  enhanced_code : enhanced_code option;
  lines : string list;
}

(** {1 Message Queue Types} *)

(** Message queued for delivery *)
type queued_message = {
  id : string;
  sender : reverse_path;
  recipients : forward_path list;
  data : string;
  received_at : float;
  auth_user : string option;
  client_ip : string;
  client_domain : domain;
}

(** {1 Security Validation Results} *)

(** SPF check result - RFC 7208 *)
type spf_result =
  | Spf_pass
  | Spf_fail
  | Spf_softfail
  | Spf_neutral
  | Spf_none
  | Spf_temperror
  | Spf_permerror

(** DKIM verification result - RFC 6376 *)
type dkim_result =
  | Dkim_pass of string
  | Dkim_fail of string
  | Dkim_temperror of string
  | Dkim_permerror of string
  | Dkim_none

(** DMARC policy - RFC 7489 *)
type dmarc_policy =
  | Dmarc_none
  | Dmarc_quarantine
  | Dmarc_reject

(** DMARC check result *)
type dmarc_result = {
  policy : dmarc_policy;
  spf_aligned : bool;
  dkim_aligned : bool;
  action : [ `Accept | `Quarantine | `Reject ];
}

(** {1 Validation Constants} *)

val max_local_part_length : int
val max_domain_length : int
val max_command_line_length : int
val max_text_line_length : int

(** {1 Validation Functions} *)

val is_valid_local_part : local_part -> bool
val is_valid_domain : domain -> bool
val is_valid_email_address : email_address -> bool
val is_local_domain : domain -> local_domains:string list -> bool

(** {1 Closed Relay Enforcement}

    Critical security function. Unauthenticated senders can only deliver to
    local domains. Authenticated users can relay anywhere. *)

val is_relay_allowed :
  state:connection_state ->
  recipient:forward_path ->
  local_domains:string list ->
  bool

(** {1 Email Address String Conversion} *)

val email_to_string : email_address -> string
val reverse_path_to_string : reverse_path -> string
val forward_path_to_string : forward_path -> string
val parse_email_address : string -> email_address option

(** {1 Standard SMTP Responses} *)

val greeting : hostname:string -> smtp_response
val ehlo_response : hostname:string -> extensions:string list -> smtp_response
val ok : ?text:string -> unit -> smtp_response
val ready_for_data : smtp_response
val starttls_ready : smtp_response
val auth_challenge : string -> smtp_response
val auth_success : smtp_response
val auth_failed : smtp_response
val auth_required : smtp_response
val temp_failure : ?text:string -> unit -> smtp_response
val perm_failure : ?text:string -> unit -> smtp_response
val relay_denied : smtp_response
val bad_sequence : smtp_response
val syntax_error : ?text:string -> unit -> smtp_response
val command_not_recognized : smtp_response
val parameter_error : ?text:string -> unit -> smtp_response
val service_closing : hostname:string -> smtp_response
val message_too_large : smtp_response
val too_many_recipients : smtp_response
val mailbox_unavailable : ?text:string -> unit -> smtp_response
val starttls_required : smtp_response
