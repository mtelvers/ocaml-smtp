(** DMARC Policy Checking - RFC 7489

    Domain-based Message Authentication, Reporting, and Conformance
    combines SPF and DKIM to verify email authenticity. *)

open Smtp_dns

(** DMARC policy action *)
type dmarc_policy =
  | Policy_none       (** No action - monitoring only *)
  | Policy_quarantine (** Mark as spam/suspicious *)
  | Policy_reject     (** Reject the message *)

(** DMARC alignment mode *)
type alignment = Strict | Relaxed

(** DMARC check result *)
type dmarc_result = {
  policy : dmarc_policy;           (** Policy from DNS record *)
  spf_aligned : bool;              (** SPF result aligned with From domain *)
  dkim_aligned : bool;             (** DKIM result aligned with From domain *)
  disposition : [ `Accept | `Quarantine | `Reject ];  (** Recommended action *)
  reason : string option;          (** Explanation *)
}

(** Parsed DMARC record *)
type dmarc_record = {
  version : string;                (** v= (must be DMARC1) *)
  policy_domain : dmarc_policy;    (** p= policy for domain *)
  policy_subdomain : dmarc_policy option;  (** sp= policy for subdomains *)
  adkim : alignment;               (** DKIM alignment mode *)
  aspf : alignment;                (** SPF alignment mode *)
  pct : int;                       (** pct= percentage to apply policy to *)
  rua : string list;               (** rua= aggregate report addresses *)
  ruf : string list;               (** ruf= forensic report addresses *)
}

(** Parse policy from string *)
let parse_policy = function
  | "none" -> Some Policy_none
  | "quarantine" -> Some Policy_quarantine
  | "reject" -> Some Policy_reject
  | _ -> None

(** Parse alignment from string *)
let parse_alignment = function
  | "r" -> Relaxed
  | "s" -> Strict
  | _ -> Relaxed  (* Default is relaxed *)

(** Parse a tag=value pair *)
let parse_tag_value s =
  match String.index_opt s '=' with
  | None -> None
  | Some i ->
    let tag = String.trim (String.sub s 0 i) in
    let value = String.trim (String.sub s (i + 1) (String.length s - i - 1)) in
    Some (tag, value)

(** Parse DMARC record from TXT value *)
let parse_dmarc_record value =
  let parts = String.split_on_char ';' value in
  let tags = List.filter_map parse_tag_value parts in
  let get tag = List.assoc_opt tag tags in

  (* Check version *)
  match get "v" with
  | Some "DMARC1" ->
    (* Parse required policy *)
    (match get "p" with
     | None -> Error "Missing p= tag"
     | Some p ->
       match parse_policy (String.lowercase_ascii p) with
       | None -> Error ("Invalid policy: " ^ p)
       | Some policy_domain ->
         let policy_subdomain =
           match get "sp" with
           | Some sp -> parse_policy (String.lowercase_ascii sp)
           | None -> None
         in
         let adkim = match get "adkim" with
           | Some a -> parse_alignment (String.lowercase_ascii a)
           | None -> Relaxed
         in
         let aspf = match get "aspf" with
           | Some a -> parse_alignment (String.lowercase_ascii a)
           | None -> Relaxed
         in
         let pct = match get "pct" with
           | Some p -> (try int_of_string p with _ -> 100)
           | None -> 100
         in
         let parse_addresses s =
           String.split_on_char ',' s
           |> List.map String.trim
           |> List.filter (fun s -> String.length s > 0)
         in
         let rua = match get "rua" with
           | Some r -> parse_addresses r
           | None -> []
         in
         let ruf = match get "ruf" with
           | Some r -> parse_addresses r
           | None -> []
         in
         Ok {
           version = "DMARC1";
           policy_domain;
           policy_subdomain;
           adkim;
           aspf;
           pct;
           rua;
           ruf;
         })
  | Some v -> Error ("Invalid DMARC version: " ^ v)
  | None -> Error "Missing v=DMARC1 tag"

(** Get organizational domain from a domain name.
    For relaxed alignment, we compare organizational domains.
    This is a simplified version - real implementations use PSL. *)
let organizational_domain domain =
  let parts = String.split_on_char '.' domain in
  match List.rev parts with
  | tld :: sld :: _ -> sld ^ "." ^ tld
  | _ -> domain  (* Return as-is if too short *)

(** Check if two domains align *)
let domains_align alignment d1 d2 =
  let d1 = String.lowercase_ascii d1 in
  let d2 = String.lowercase_ascii d2 in
  match alignment with
  | Strict -> d1 = d2
  | Relaxed ->
    let org1 = organizational_domain d1 in
    let org2 = organizational_domain d2 in
    org1 = org2

(** Look up DMARC record for a domain *)
let lookup_dmarc_record dns domain =
  let dmarc_domain = "_dmarc." ^ domain in
  match lookup_txt dns dmarc_domain with
  | Error Not_found ->
    (* Try organizational domain *)
    let org_domain = organizational_domain domain in
    if org_domain <> domain then
      let org_dmarc_domain = "_dmarc." ^ org_domain in
      match lookup_txt dns org_dmarc_domain with
      | Error _ -> Error "No DMARC record"
      | Ok records ->
        let dmarc_records = List.filter (fun r ->
          let r_lower = String.lowercase_ascii r in
          String.length r_lower >= 8 &&
          String.sub r_lower 0 8 = "v=dmarc1"
        ) records in
        (match dmarc_records with
         | [] -> Error "No DMARC record"
         | record :: _ -> parse_dmarc_record record)
    else
      Error "No DMARC record"
  | Error _ -> Error "DNS lookup failed"
  | Ok records ->
    let dmarc_records = List.filter (fun r ->
      let r_lower = String.lowercase_ascii r in
      String.length r_lower >= 8 &&
      String.sub r_lower 0 8 = "v=dmarc1"
    ) records in
    match dmarc_records with
    | [] -> Error "No DMARC record"
    | record :: _ -> parse_dmarc_record record

(** Check DMARC policy for a message.

    @param dns DNS resolver
    @param from_domain Domain from the From header (RFC 5322.From)
    @param spf_result Result of SPF check
    @param spf_domain Domain used for SPF check (MAIL FROM or HELO)
    @param dkim_result Result of DKIM verification
    @return DMARC check result *)
let check ~dns ~from_domain ~spf_result ~spf_domain ~dkim_result =
  (* Look up DMARC record *)
  match lookup_dmarc_record dns from_domain with
  | Error msg ->
    (* No DMARC record - accept *)
    {
      policy = Policy_none;
      spf_aligned = false;
      dkim_aligned = false;
      disposition = `Accept;
      reason = Some msg;
    }
  | Ok record ->
    (* Check SPF alignment *)
    let spf_pass = match spf_result.Smtp_spf.result with
      | Smtp_spf.Spf_pass -> true
      | _ -> false
    in
    let spf_aligned = spf_pass && domains_align record.aspf from_domain spf_domain in

    (* Check DKIM alignment *)
    let (dkim_pass, dkim_domain) = match dkim_result with
      | Smtp_dkim.Dkim_pass d -> (true, Some d)
      | _ -> (false, None)
    in
    let dkim_aligned = match dkim_domain with
      | Some d -> dkim_pass && domains_align record.adkim from_domain d
      | None -> false
    in

    (* Determine disposition based on alignment *)
    let authenticated = spf_aligned || dkim_aligned in
    let disposition =
      if authenticated then
        `Accept
      else
        (* Apply policy based on pct *)
        if record.pct < 100 && Random.int 100 >= record.pct then
          `Accept  (* Not in sampled percentage *)
        else
          match record.policy_domain with
          | Policy_none -> `Accept
          | Policy_quarantine -> `Quarantine
          | Policy_reject -> `Reject
    in
    let reason =
      if authenticated then None
      else Some (Printf.sprintf "SPF %s, DKIM %s"
                   (if spf_pass then "pass (unaligned)" else "fail")
                   (if dkim_pass then "pass (unaligned)" else "fail"))
    in
    {
      policy = record.policy_domain;
      spf_aligned;
      dkim_aligned;
      disposition;
      reason;
    }

(** Convert policy to string *)
let policy_to_string = function
  | Policy_none -> "none"
  | Policy_quarantine -> "quarantine"
  | Policy_reject -> "reject"

(** Convert disposition to string *)
let disposition_to_string = function
  | `Accept -> "accept"
  | `Quarantine -> "quarantine"
  | `Reject -> "reject"

(** Format DMARC result for Authentication-Results header *)
let format_auth_results result from_domain =
  let pass_fail = match result.disposition with
    | `Accept when result.spf_aligned || result.dkim_aligned -> "pass"
    | `Accept -> "none"
    | `Quarantine -> "fail"
    | `Reject -> "fail"
  in
  Printf.sprintf "dmarc=%s (p=%s) header.from=%s"
    pass_fail
    (policy_to_string result.policy)
    from_domain
