(** SPF Verification - RFC 7208

    Sender Policy Framework validation to verify that a sending
    mail server is authorized by the domain owner. *)

(** SPF check result per RFC 7208 Section 2.6 *)
type spf_result =
  | Spf_pass          (** Authorized sender *)
  | Spf_fail          (** Unauthorized - reject *)
  | Spf_softfail      (** Unauthorized - accept but mark *)
  | Spf_neutral       (** No assertion *)
  | Spf_none          (** No SPF record *)
  | Spf_temperror     (** Temporary error (DNS failure) *)
  | Spf_permerror     (** Permanent error (syntax error) *)

(** SPF check result with details *)
type spf_check_result = {
  result : spf_result;
  domain : string;
  explanation : string option;
}

(** Check SPF for a sender's domain.

    @param dns DNS resolver
    @param client_ip IP address of the connecting client
    @param sender_domain Domain from MAIL FROM (or HELO if null sender)
    @return SPF check result *)
val check :
  dns:Smtp_dns.t ->
  client_ip:Smtp_dns.ip_addr ->
  sender_domain:string ->
  spf_check_result

(** Convert SPF result to string *)
val result_to_string : spf_result -> string

(** Format SPF result for Received-SPF header *)
val format_received_spf : spf_check_result -> Smtp_dns.ip_addr -> string -> string
