(** DMARC Policy Checking - RFC 7489

    Domain-based Message Authentication, Reporting, and Conformance
    combines SPF and DKIM to verify email authenticity. *)

(** DMARC policy action *)
type dmarc_policy =
  | Policy_none       (** No action - monitoring only *)
  | Policy_quarantine (** Mark as spam/suspicious *)
  | Policy_reject     (** Reject the message *)

(** DMARC check result *)
type dmarc_result = {
  policy : dmarc_policy;           (** Policy from DNS record *)
  spf_aligned : bool;              (** SPF result aligned with From domain *)
  dkim_aligned : bool;             (** DKIM result aligned with From domain *)
  disposition : [ `Accept | `Quarantine | `Reject ];  (** Recommended action *)
  reason : string option;          (** Explanation *)
}

(** Check DMARC policy for a message.

    @param dns DNS resolver
    @param from_domain Domain from the From header (RFC 5322.From)
    @param spf_result Result of SPF check
    @param spf_domain Domain used for SPF check (MAIL FROM or HELO)
    @param dkim_result Result of DKIM verification
    @return DMARC check result *)
val check :
  dns:Smtp_dns.t ->
  from_domain:string ->
  spf_result:Smtp_spf.spf_check_result ->
  spf_domain:string ->
  dkim_result:Smtp_dkim.dkim_result ->
  dmarc_result

(** Convert policy to string *)
val policy_to_string : dmarc_policy -> string

(** Convert disposition to string *)
val disposition_to_string : [ `Accept | `Quarantine | `Reject ] -> string

(** Format DMARC result for Authentication-Results header *)
val format_auth_results : dmarc_result -> string -> string
