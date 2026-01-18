(** SMTP Authentication Module

    Implements SASL authentication ({{:https://datatracker.ietf.org/doc/html/rfc4954}RFC 4954})
    for SMTP. *)

(** Authentication backend interface *)
module type AUTH = sig
  type t

  (** Create an authentication backend.
      @param service_name PAM service name (e.g., "smtpd") *)
  val create : service_name:string -> t

  (** Authenticate a user with username and password.
      @return true if authentication succeeds *)
  val authenticate : t -> username:string -> password:string -> bool
end

(** PAM-based authentication backend *)
module Pam_auth : sig
  include AUTH

  (** Check if PAM is available on this system *)
  val is_available : unit -> bool
end

(** Mock authentication backend for testing *)
module Mock_auth : sig
  include AUTH

  (** Add a user with the given credentials *)
  val add_user : t -> username:string -> password:string -> unit

  (** Remove a user *)
  val remove_user : t -> username:string -> unit

  (** List all registered usernames *)
  val list_users : t -> string list
end
