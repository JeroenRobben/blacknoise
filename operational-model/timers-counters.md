# Timers

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
        
5. **renewCookieSecretValue**
    - **Associated with:** WG interface
    - **Start:** System start
    - **Duration:** 120 seconds
    - **Stop:** Never
    - **Action:** Restart timer, renew cookie secret value (R_m)

## Counters

1. **sendCounter**
	- Associated with: secure session
2. receiveCounter
	- Associated with: secure session