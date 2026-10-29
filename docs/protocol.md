# Wire protocol

This document defines protocol version 1's stream framing and common JSON envelope.
Client and server implementations must update this document, the shared codec, and
affected tests whenever the contract changes.

## Transport and framing

Messages travel over a TLS-protected TCP byte stream. TLS protects transport data;
it does not replace message validation.

Each frame contains a four-byte unsigned big-endian payload length followed by that
many payload bytes. The length excludes the four-byte prefix.

| Field | Size | Constraint |
| --- | ---: | --- |
| Payload length | 4 bytes | 1 through 65,536 bytes, inclusive |
| Payload | Declared length | One UTF-8 JSON object |

A zero length or a length above 65,536 bytes is a framing error. Receivers must
enforce the limit as soon as the header is available, before allocating or waiting
for the declared payload.

TCP reads may split a header or payload at any byte and may coalesce multiple frames.
A receiver must retain partial input, return only complete payloads, and preserve the
order of frames in a coalesced sequence. There is no delimiter-based resynchronization.
After a framing error, decoding stops and the transport must close the connection;
a decoder reset is only for a new stream.

## JSON envelope

Every payload is a UTF-8 JSON object with these top-level fields:

| Field | Presence | Value |
| --- | --- | --- |
| `version` | Required | Unsigned 32-bit integer; version 1 only |
| `type` | Required | Registered message type string |
| `requestId` | Optional | String containing 1 to 128 UTF-16 code units |
| `payload` | Required | JSON object; may be empty |

Version-1 receivers reject additional top-level fields, missing fields, incorrect
field types, invalid UTF-8, malformed JSON, and non-object JSON roots. JSON must use
strict RFC 8259 syntax: non-standard numbers, invalid escapes, and literal control
characters are rejected even if a permissive parser accepts them. Duplicate object
member names, including names that become equal after escape decoding, are rejected
at every depth. JSON nesting is limited to 64 levels.

Senders use compact JSON and must keep the complete encoded frame within the size
limit.

A request sender assigns `requestId` as an opaque correlation identifier. A response
to that request echoes the same value. Server-originated events omit it unless they
correspond to a specific request. Receivers must not interpret its contents.

Example heartbeat request:

```json
{"version":1,"type":"ping","requestId":"request-42","payload":{}}
```

## Registered message types

Version 1 currently registers these common types. Feature-specific request, response,
and event types must be added to the shared registry before handlers use them.

| Type | Direction | Payload |
| --- | --- | --- |
| `ping` | Either | Empty object |
| `pong` | Either | Empty object; echoes `requestId` when answering a ping |
| `error` | Either | Error object described below |

Handlers must validate message-specific payload requirements before dispatch.

An error payload contains:

```json
{"code":"invalid_message","message":"The message is invalid"}
```

- `code` is one of the stable strings below.
- `message` is safe, human-readable diagnostic text. It must not contain credentials,
  tokens, SQL details, provider responses, or other sensitive data.
- `requestId` is echoed when the failing request's ID is known.

## Error codes

| Code | Meaning |
| --- | --- |
| `invalid_frame` | Empty, oversized, or otherwise invalid framing |
| `invalid_message` | Invalid UTF-8, JSON, envelope fields, or outgoing envelope data |
| `unsupported_version` | A valid integer version that the endpoint does not support |
| `unknown_message_type` | A message type absent from the shared registry |
| `invalid_request` | Structurally valid message with invalid operation data or state |
| `unauthenticated` | Authentication is required or the supplied session is not valid |
| `invalid_credentials` | Generic local login failure; does not reveal account existence |
| `username_taken` | Signup cannot reserve the requested normalized username |
| `rate_limited` | Authentication or messaging rate limit was exceeded |
| `unavailable` | A required dependency or service is temporarily unavailable |
| `internal_error` | Unexpected failure without exposed internal details |

`ErrorCode::None` is a local success sentinel and has no wire representation.

## Versioning and compatibility

Version 1 is the only accepted version. An endpoint reports `unsupported_version`
for a well-formed integer version it does not support and
`unknown_message_type` for an unregistered type. It does not silently downgrade or
dispatch unknown messages.

Additive fields within operation payloads require explicit validation and compatibility
review. Changes to the envelope, framing, limits, or required semantics require a new
protocol version rather than an undocumented version-1 extension.
