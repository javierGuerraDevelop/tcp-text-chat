# Wire protocol

This document defines protocol version 1's stream framing and common JSON envelope.
Client and server implementations must update this document, the shared codec, and
affected tests whenever the contract changes.

## Transport and framing

Messages travel over a TLS-protected TCP byte stream. TLS protects transport data;
it does not replace message validation. Both endpoints require TLS 1.2 or newer and
allow TLS 1.3 negotiation. There is no plaintext fallback.

Servers load a PEM certificate chain and private key from explicit configuration.
Clients verify the certificate chain and the configured peer name against system
trust roots or an explicit private-CA PEM file. Certificate validation failures
terminate negotiation. Server configuration bounds concurrent connections, pending
TCP connections, and TLS negotiation time.

After negotiation, each endpoint sends a `ping` every 15 seconds by default and
closes the connection after 45 seconds without incoming network activity. These
intervals are configurable and measured with a monotonic clock. Any incoming data
resets the inactivity deadline; a valid ping receives an automatic pong with the
same request ID.

Each socket accepts at most 262,160 bytes of queued plaintext and encrypted output
by default. A sender whose next frame would exceed that bound must wait for output
to drain; the local send operation reports `unavailable` rather than growing the
queue. Graceful shutdown stops new sends, flushes accepted output, and aborts the
socket if the configured three-second shutdown deadline expires. A protocol or
framing failure sends an `error` envelope when output capacity permits before
closing the connection.

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
order of frames in a coalesced sequence. The shared decoder retains at most 65,540
bytes (one maximum frame and its header). Its append operation reports how many bytes
were consumed; when it returns zero because the buffer is full, the caller drains
complete frames before retrying the unconsumed suffix. A full buffer is backpressure,
not a protocol error.

There is no delimiter-based resynchronization. After a framing error, decoding stops
and the transport must close the connection; a decoder reset is only for a new stream.

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
at every depth. JSON object/array nesting is limited to 64 levels, with the root
container counted as level 1; scalar content does not add a container level.

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
| `auth.signup` | Client to server | Local username, password, and optional display name |
| `auth.login` | Client to server | Local username and password |
| `auth.logout` | Client to server | Opaque session token |
| `auth.session` | Client to server | Opaque session token for reconnect authentication |
| `auth.result` | Server to client | Authenticated identity or logout result |
| `auth.oauth.start` | Client to server | Canonical provider identifier |
| `auth.oauth.status` | Client to server | Opaque browser-flow handle |
| `auth.oauth.complete` | Client to server | Flow handle and distinct single-use handoff |
| `auth.oauth.result` | Server to client | Browser-flow state and authorized fields |

Handlers must validate message-specific payload requirements before dispatch.

## Local authentication and sessions

`auth.signup` accepts `username`, `password`, and an optional `displayName`. Usernames
are trimmed, Unicode-normalized, and case-folded for uniqueness; they contain 3 to 32
letters, numbers, marks, `.`, `_`, or `-`. Display names contain 1 to 64 printable
characters and cannot have leading or trailing whitespace. Passwords are 8 to 1024
UTF-8 bytes and are never logged or persisted in plaintext.

`auth.login` accepts `username` and `password`. Unknown usernames, OAuth-only
accounts, and incorrect passwords all return `invalid_credentials` with the same
safe message. Signup returns `username_taken` when normalization collides with an
existing account.

Successful signup and login responses use `auth.result` with `user`, `sessionToken`,
and `expiresAt`. The token is 32 cryptographically random bytes encoded as 43
unpadded Base64URL characters. The server stores only a 32-byte digest of the token;
the bearer value is returned to the client only when issued and is kept in memory by
the client. `expiresAt` is UTC milliseconds since the Unix epoch. Sessions expire
after seven days by default and can be revoked with `auth.logout`. Expiration or
revocation also disconnects every live connection using that session; the connection
that requested logout may remain connected in an unauthenticated state.

`auth.session` presents the token to authenticate a new TLS connection. Its result
contains `user` and `expiresAt` but no new token. A connection that is already
authenticated cannot log in, sign up, or resume another session without logging out
first. Logout returns `{ "revoked": true }`, including when the presented token is
already expired or unknown. Invalid token syntax is rejected.

Authentication attempts are bounded per connection and per source IP in fixed
60-second windows. Excess attempts return `rate_limited`. Unauthenticated
connections also have a 30-second deadline by default. Password hashing runs in a
bounded worker pool, and each connection has a bounded number of pending operations.

## Browser OAuth

`auth.oauth.start` accepts `{ "provider": "provider-id" }`. The `auth.oauth.result`
response has `status: "started"`, an opaque `flow`, an HTTPS `authorizationUrl`, and
`expiresAt`. The desktop opens this URL in the system browser. Each flow is bound to
its originating TLS connection, exact server HTTPS redirect URI, state, and PKCE
verifier. OpenID flows also bind a nonce. Provider implementations must validate the
code exchange, PKCE verifier, token signature, issuer, and audience before returning
an identity; the coordinator independently checks the returned claims and nonce.

The client polls with `auth.oauth.status` and its `flow`. Results have status
`pending`, `ready`, or `failed`, plus `flow` and `expiresAt`. Only `ready` includes a
short-lived `handoff`. `auth.oauth.complete` presents both `flow` and `handoff` and
returns the normal `auth.result` with a newly issued chat session. A handoff is not a
session token and is never accepted by `auth.session`. Redemption consumes it before
asynchronous session issuance, so it cannot be replayed. Browser HTML and callback
responses never contain a handoff or chat session.

Browser flows expire after five minutes by default; handoffs expire after one minute.
Disconnecting cancels flows and handoffs. An active browser flow has its own bounded
connection deadline, and status polling is separately limited to 120 requests per
connection in a 60-second window. Provider denial, invalid or replayed state, bad
identity claims, and expired flows fail without exposing provider responses.

The server resolves only the exact `(provider, provider_subject)` identity. It never
merges accounts by email, display name, or username. New OAuth-only users receive a
server-generated unique username and have no local password hash. SQLite persists
only user and provider-identity mappings, not provider tokens, flow handles, state,
PKCE verifiers, handoffs, or plaintext chat session tokens.

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
