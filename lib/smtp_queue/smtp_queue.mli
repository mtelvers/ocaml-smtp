(** SMTP Message Queue

    Stores messages accepted by the SMTP server for delivery or local storage. *)

open Smtp_types

(** Queue error types *)
type error =
  | Queue_full
  | Message_too_large
  | Storage_error of string

(** Queue statistics *)
type stats = {
  pending : int;
  total_size : int64;
}

(** Queue backend interface *)
module type QUEUE = sig
  type t

  (** Create a new queue *)
  val create : unit -> t

  (** Enqueue a message.
      @return Ok queue_id on success, Error on failure *)
  val enqueue : t -> queued_message -> (string, error) result

  (** Dequeue the next message for delivery.
      @return Some message if available, None if queue is empty *)
  val dequeue : t -> queued_message option

  (** Peek at up to n messages without removing them *)
  val peek : t -> int -> queued_message list

  (** Get a specific message by ID *)
  val get : t -> id:string -> queued_message option

  (** Mark a message as successfully delivered and remove from queue *)
  val mark_delivered : t -> id:string -> (unit, error) result

  (** Mark a message as failed with reason *)
  val mark_failed : t -> id:string -> reason:string -> (unit, error) result

  (** Get queue statistics *)
  val get_stats : t -> stats
end

(** In-memory queue backend (for development/testing) *)
module Memory_queue : QUEUE

(** File-based queue backend (for production) *)
module File_queue : sig
  include QUEUE

  (** Create a queue with a specific spool directory *)
  val create_with_path : base_path:string -> t
end
