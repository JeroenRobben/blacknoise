# Timers

> **Work in progress.** This document serves as a working note and is incomplete. It should not be relied upon when implementing WireGuard.

## Initiator-only timers

1. retransmitHandshake (6.2, 6.4)
   - **Start:** Handshake initiation sent
   - **Duration:** `RekeyTimeout + jitter`
   - **Stop:** Handshake completed
   - **Action:**
       - Send new handshake initiation with _new ephemeral keys_
       - Restart timer
2. retransmitHandshakeMaxAttempts (6.4)
   - **Start:**
       - First handshake attempt
       - Attempting to send new transport data message
        
   - **Duration:** `RekeyAttemptTime`
   - **Stop:** Handshake completed
   - **Action:**
       - Stop handshake attempts, i.e., stop `retransmitHandshake` timer
        
   - **Note:** Some implementations replace this timer with a counter that limits the number of handshake retries. The maximum number of handshake attempts is then `RekeyAttemptTime / RekeyTimeout`.
   - **wireguard-go:** Uses a counter (`handshakeAttempts`, `atomic.Uint32`) instead of a timer. The limit is `MaxTimerHandshakes = RekeyAttemptTime / RekeyTimeout = 18`. The counter is incremented on each retry in `expiredRetransmitHandshake` and checked before sending a new initiation (`device/timers.go`).

## Shared timers

1. **sendKeepalive** (6.5)
    - **Associated with:** Secure session
    - **Start:** Received transport data message from other peer
    - **Duration:** `KeepAliveTimeout`
    - **Stop:** Sent transport data message to other peer
    - **Action:** Send keepalive message
    - **Note:** The WireGuard website and Peter Wu thesis give other semantics regarding the timeout compared to what is described in the white paper. The white paper says: `\texit{If a peer has received a validly-authenticated transport data message (section 5.4.6), but does not have any packets itself to send back for \texttt{KeepAliveTimeout} seconds, it sends a keepalive message.}` Here it seems that the keepalive is send after `KeepAliveTimeout` seconds after receiving the last data message. On the website and Peter wu thesis, it is stated that the keepalive is immediately sent when receiving a data message but not have transmitted a data message for `KeepAliveTimeout` seconds.
        
2. **zeroKeyMaterial** (6.3)
    - **Associated with:** Peer
    - **Start:** Handshake completed
    - **Duration:** `RejectAfterTime * 3`
    - **Action:**
        - Zero memory of previous, current, and next secure session
        - Zero any partially-completed handshake states and ephemeral keys
            
3. **initiateNewHandshakeIfPeerUnresponsive**
    - **Associated with:** Secure session
    - **Start:** Sent transport message to other peer
    - **Duration:** `KeepAliveTimeout + RekeyTimeout`
    - **Stop:** Received transport data message from other peer
    - **Action:** Initiate new handshake
        
4. **expireCookieForPeer**
    - **Associated with:** Peer
    - **Start:** Received cookie reply message
    - **Duration:** 120 seconds
    - **Stop:** /
    - **Action:** Clear stored cookie for this peer
    - **wireguard-go:** No explicit timer. Instead, a `cookieSet` timestamp is stored and `time.Since(cookieSet) > CookieRefreshTime` is checked lazily on use (`device/cookie.go`).

5. **renewCookieSecretValue**
    - **Associated with:** WG interface
    - **Start:** System start
    - **Duration:** 120 seconds
    - **Stop:** Never
    - **Action:** Restart timer, renew cookie secret value (R_m)
    - **wireguard-go:** No explicit timer. Instead, a `secretSet` timestamp is stored and `time.Since(secretSet) > CookieRefreshTime` is checked lazily on use (`device/cookie.go`).

6. **persistentKeepalive**
    - **Associated with:** Peer
    - **Start:** Any authenticated packet (data, keepalive, or handshake) sent or received, if a persistent keepalive interval is configured
    - **Duration:** Configured `persistentKeepaliveInterval` (user-defined, in seconds)
    - **Stop:** /
    - **Action:** Send keepalive message, restart timer
    - **Note:** This timer is not described in the WireGuard white paper. It is a practical extension present in implementations to keep stateful NAT/firewall mappings alive.

## Counters

1. **sendCounter**
	- Associated with: secure session
2. receiveCounter
	- Associated with: secure session