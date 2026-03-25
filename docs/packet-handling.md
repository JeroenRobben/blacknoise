# Message handling per message type

> **Work in progress.** This document serves as a working note and is incomplete. It should not be relied upon when implementing WireGuard.

## Receiving handshake initiation

1. Verify `msg.mac1`
2. If under load: verify `mac2`. If invalid: drop packet, return cookie reply
3. Decrypt `msg.static`, verify (H_i)
4. Lookup peer, drop packet if peer doesn't exist
5. Decrypt `msg.timestamp`, verify (H_i)
6. Check if timestamp value (\ge) last timestamp value for that peer. If true, update timestamp. If not, drop packet
7. Update IP endpoint from peer using packet
8. Create new session in `ResponseSent` state, send handshake response

## Receiving handshake response

1. Verify `msg.mac1`
2. If under load: verify `mac2`. If invalid: drop packet, return cookie reply
3. Check if (I_i) matches secure session in `handshakeInitSent` state
4. Verify `msg.empty`
5. Update IP endpoint from peer using packet.
6. Send queued data packet(s), or a keepalive. (Some implementations always send a keepalive first)

## Receiving cookie reply message

1. Lookup if Receiver index matches secure session in `initSent` or `reponseSent` state, drop packet if not
2. Decrypt / authenticate encrypted cookie
3. Check if cookie correctly authenticates `mac1` from message that triggered the cookie
4. ??Update IP endpoint from peer using packet. -> "Official" WireGuard implementations seem to not update the peers endpoint from cookie replies, but process them nevertheless
5. Store cookie value, start `expireCookieForPeer` timer (or use some other mechanism to keep track of how long this cookie should be used for calculating mac2)
    

Receiving (+ handling) cookies in `responseSent` state (thus cookies sent by the initiator) is not explicitly described in the white paper.

## Receiving data packet

1. UDP transport data packet is received.
2. Validate packet — drop packet if invalid:
    - Associated with secure session?
    - Message counter valid?
    - Authentication and decryption successful with session's receiving symmetric key?
3. Validate session — drop packet if invalid:
    - Session's receive counter < `RejectAfterMessages`
    - `SessionAge` < `RejectAfterTime`
4. Update timers:
    - Restart `sendKeepalive` timer.
5. If session = initiator **and**  
    `SessionAge` >= `RejectAfterTime` - `KeepAliveTimeout` - `RekeyTimeout`:
    - Initiate new handshake.
6. Cryptokey routing table check:
    - Is inner packet a valid IP packet?
    - Does the source IP of the inner packet route correctly according to this peer's cryptokey routing table?
7. Update IP endpoint from peer using packet.
8. Accept packet.
    

## Sending data packet

1. Plaintext packet reaches `wg0`.
2. Destination IP is checked to find the matching peer in the cryptokey routing table.
3. Find session associated with peer:
    - If no session is found, or (`SessionAge` >= `RejectAfterTime`: initiate handshake and queue packet.
    - If handshake process is ongoing: restart `retransmitHandshakeMaxAttempts` timer.
4. If session = initiator **and** (`SessionAge` >= `RekeyAfterTime`:
    - Initiate new handshake.
5. Update timers:
    - Restart `initiateNewHandshakeIfPeerUnresponsive` timer.
6. Zero pad packet payload to a multiple of 16 bytes, create WireGuard packet.
7. Transmit packet.