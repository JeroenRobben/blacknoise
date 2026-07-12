# Message handling per message type

> **Always refer to the WireGuard whitepaper, website and reference implementations when implementing WireGuard.**

State and field names below match `state-machine.md` and `state_machine.py`.

## Receiving handshake initiation

1. Verify `msg.mac1`. Drop if invalid.
2. If under load: verify `msg.mac2`. If invalid: drop the packet and return a cookie reply.
3. Mix `msg.ephemeral` into the running handshake hash, then decrypt `msg.static`, verifying the AEAD tag against the *current* `H_i` (i.e. `H_i` after `msg.ephemeral` has been hashed in but before `msg.static` has). Drop on failure.
4. Look up the peer by the decrypted static public key. Drop if no peer matches.
5. Mix `msg.static` into `H_i`, derive `κ`, and decrypt `msg.timestamp`, verifying the AEAD tag against the updated `H_i`. Drop on failure.
6. Compare the decrypted timestamp as an opaque big-endian 96-bit value against the peer's `highest_tai64n`. If strictly greater, update `highest_tai64n`. Otherwise drop.
7. Update the peer's `endpoint` to the source address of the received packet.
8. Create a new session in `ResponseSent` state and install it as the peer's `next_session`. Send the handshake response.

If the peer already has an `ActiveInitiator` or `ActiveResponder` session, it stays as `current_session` The new `ResponseSent` session occupies `next_session` and is promoted to `current_session` only on receipt of the first valid transport message under it.

## Receiving handshake response

1. Verify `msg.mac1`. Drop if invalid.
2. If under load: verify `msg.mac2`. If invalid: drop the packet and return a cookie reply.
3. Look up `msg.receiver` (`I_i`) and confirm it matches a session in `InitSent` state. Drop if no match.
4. Verify the AEAD tag on `msg.empty`. Drop on failure.
4. Derive `T_send_i` and `T_recv_i`.
5. Update the peer's `endpoint` to the source address of the received packet.
6. Promote the session to `ActiveInitiator` and install it as `current_session`, rotating the previous `current_session` into `previous_session`.
7. Send any queued data packets, or a keepalive if there are none.

## Receiving cookie reply

1. Look up `msg.receiver` and confirm it matches a session in `InitSent` or `ResponseSent` state. Drop if no match.
2. Decrypt and authenticate the encrypted cookie, with the `mac1` of the message that triggered the cookie as the AEAD additional authenticated data. Drop on failure.
3. Store the cookie value and current time as the peer's `cookie` / `cookie_received_at`. The cookie is treated as expired after 120 s.
4. Do **not** update the peer's `endpoint` from a cookie reply, and do **not** retransmit the previously sent handshake message. The next handshake retransmission, driven by `retransmitHandshake`, will incorporate the cookie via `mac2` (whitepaper §6.6).

The cookie-reply-in-`ResponseSent` flow (cookies sent by the initiator to the responder) is not explicitly described in the whitepaper but follows symmetrically from the message format.

## Receiving transport data packet

1. Look up the message's `receiver` index. Drop if it does not match `previous_session`, `current_session`, or `next_session` for any peer.
2. Validate the message:
   - Counter is within the receive window of the matched session.
   - AEAD authentication and decryption succeed with the session's `T_recv`.
3. Validate the matched session:
   - Receive counter < `RejectAfterMessages`.
   - `SessionAge < RejectAfterTime`.
4. Update the receive window for this counter.
5. If the matched session is `next_session`, rotate: `current -> previous`, `next -> current`, zero the old `previous`.
6. Restart `sendKeepalive` timer.
7. If the local peer is the session's initiator and `SessionAge ≥ RejectAfterTime − KeepAliveTimeout − RekeyTimeout`: initiate a new handshake (opportunistic rekey on receive path).
8. Cryptokey-routing check on the decrypted inner packet:
   - Verify it is a valid IP packet.
   - Verify the inner packet's **source** address lies within this peer's configured `AllowedIPs`. Drop otherwise.
9. Update the peer's `endpoint` to the source of the outer UDP packet.
10. Deliver the inner packet to the network stack.

## Sending transport data packet

1. Plaintext packet reaches `wg0`.
2. Look up the destination IP in the cryptokey routing table to find the matching peer. If no peer matches: drop, send ICMP no-route-to-host, and return `-ENOKEY`.
3. Find the session for that peer:
   - If no `current_session`, or `SessionAge ≥ RejectAfterTime`, or messages-sent ≥ `RejectAfterMessages`: queue the packet, initiate a new handshake, return.
   - If a handshake is already in progress: queue the packet and reset the `RekeyAttemptTime` deadline for this peer (the user explicitly attempting to send transport data is the reset condition for `retransmitHandshakeMaxAttempts`).
4. If the local peer is the initiator and either `SessionAge ≥ RekeyAfterTime` or messages-sent ≥ `RekeyAfterMessages`: initiate a new handshake (alongside continuing to send under the current session).
5. Cancel `sendKeepalive`; restart `initiateNewHandshakeIfPeerUnresponsive`.
6. Zero-pad the packet payload to a multiple of 16 bytes, encrypt with `T_send` and the next `sendCounter`, increment `sendCounter`.
7. Encapsulate and transmit.
