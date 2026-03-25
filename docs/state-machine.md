# WireGuard State Machine

> **Work in progress.** This document serves as working note and is incomplete. It should not be relied upon when implementing WireGuard.

The aim here is to define a complete operational state machine for WireGuard implementations. Currently, only the state machine of a single secure session is described.

---

# States

| State | Description                                                                                                                                                                         | Stored data                                                                                                                                                                |
|-------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Idle** | Initial state. No handshake has been started.                                                                                                                                       | Static session config only (own key pair, peer public key, PSK).                                                                                                           |
| **InitSent** | We have sent a handshake initiation and are waiting for a handshake response or cookie from the responder.                                                                          | Intermediate chaining value `c_i` and hash `h_i`; original handshake initiation packet (for cookie authentication); session index.                                         |
| **ResponseSent** | We have received and processed a handshake initiation (as responder) and sent a handshake response. Waiting for the first transport packet from the initiator or a cookie.          | `t_recv_r`, `t_send_r` (transport keys); original handshake response packet (for cookie authentication); session index; peer session index.                                |
| **ActiveInitiator** | Fully established session (initiator). Both directions of transport data can flow.                                                                                                  | `t_send_i`, `t_recv_i` (transport keys); outgoing nonce counter; sliding window for replay protection; session index; peer session index.                                  |
| **ActiveResponder** | Fully established session (responder). Both directions of transport data can flow.                                                                                                  | `t_send_r`, `t_recv_r` (transport keys); `ctr_send` (outgoing counter, starts at 0); `ctr_recv` (sliding window for replay protection); session index; peer session index. |
| **Expired** | Terminal state. REJECT-AFTER-TIME has elapsed or the (theoretical) maximum message count has been reached. No further packets can be sent or received. | None — all keying material must be zeroed.                                                                                                                                 |

---


# State Transitions

[Image](https://dreampuf.github.io/GraphvizOnline/?engine=dot#digraph%20WireGuardSecureSession%20%7B%0A%0A%20%20idle%20%20%20%20%20%20%20%20%20%20%20%20%20%5Bshape%3DMdiamond%2C%20label%3D%22Idle%22%5D%3B%0A%20%20initSent%20%20%20%20%20%20%20%20%20%5Blabel%3D%22InitSent%22%5D%3B%0A%20%20responseSent%20%20%20%20%20%5Blabel%3D%22ResponseSent%22%5D%3B%0A%20%20activeInitiator%20%20%5Blabel%3D%22Active%20(Initiator)%22%5D%3B%0A%20%20activeResponder%20%20%5Blabel%3D%22Active%20(Responder)%22%5D%3B%0A%20%20expired%20%20%20%20%20%20%20%20%20%20%5Bshape%3DMsquare%2C%20label%3D%22Expired%22%5D%3B%0A%20%20%20%20%0A%20%20idle%20-%3E%20initSent%0A%20%20%20%20%5Blabel%3D%22%E2%8A%A5%20%2F%20hs_initiation%22%5D%3B%0A%20%20%20%20%0A%20%20initSent%20-%3E%20initSent%0A%20%20%20%20%5Blabel%3D%22cookie_reply%20%2F%20hs_initiation(mac2)%22%5D%3B%0A%20%20%20%20%0A%20%20initSent%20-%3E%20initSent%0A%20%20%20%20%5Blabel%3D%22hs_response%20%2F%20cookie_reply%22%20color%3D%22red%22%5D%3B%0A%0A%20%20initSent%20-%3E%20activeInitiator%0A%20%20%20%20%5Blabel%3D%22hs_response%20%2F%20transport_data%22%5D%3B%0A%0A%20%20idle%20-%3E%20responseSent%0A%20%20%20%20%5Blabel%3D%22hs_initiation%20%2F%20hs_response%22%5D%3B%0A%0A%20%20idle%20-%3E%20idle%0A%20%20%20%20%5Blabel%3D%22hs_initiation%20%2F%20cookie_reply%22%20color%3D%22red%22%5D%3B%0A%0A%20%20responseSent%20-%3E%20activeResponder%0A%20%20%20%20%5Blabel%3D%22transport_data%20%2F%20%E2%8A%A5%22%5D%3B%0A%0A%20%20responseSent%20-%3E%20responseSent%0A%20%20%20%20%5Blabel%3D%22cookie_reply%20%2F%20hs_response(mac2)%22%5D%3B%0A%20%20%20%20%0A%20%20activeInitiator%20-%3E%20activeInitiator%0A%20%20%20%20%20%20%5Blabel%3D%22transport_data%20%2F%20%E2%8A%A5%22%5D%3B%0A%20%20activeInitiator%20-%3E%20activeInitiator%0A%20%20%20%20%20%20%5Blabel%3D%22%E2%8A%A5%20%2F%20transport_data%22%5D%3B%0A%20%20%20%20%20%20%0A%20%20activeResponder%20-%3E%20activeResponder%0A%20%20%20%20%20%20%5Blabel%3D%22transport_data%20%2F%20%E2%8A%A5%22%5D%3B%0A%20%20activeResponder%20-%3E%20activeResponder%0A%20%20%20%20%20%20%5Blabel%3D%22%E2%8A%A5%20%2F%20transport_data%22%5D%3B%0A%0A%20%20initSent%20-%3E%20expired%0A%20%20%20%20%5Blabel%3D%22expiration%22%5D%3B%0A%0A%20%20responseSent%20-%3E%20expired%0A%20%20%20%20%5Blabel%3D%22expiration%22%5D%3B%0A%0A%20%20activeInitiator%20-%3E%20expired%0A%20%20%20%20%5Blabel%3D%22expiration%22%5D%3B%0A%0A%20%20activeResponder%20-%3E%20expired%0A%20%20%20%20%5Blabel%3D%22expiration%22%5D%3B%0A%20%0A%7D)

## Notes

- Sending cookie replies in initSent state (as an answer to a handshake response) is not explicitly described in the whitepaper. There should never be an immediate handshake retransmission when receiving a cookie reply (to not have a vector for amplification attacks I guess)?
- Implementations should take care to reject handshake response replays in activeInitiator state.

```
digraph WireGuardSecureSession {

  idle             [shape=Mdiamond, label="Idle"];
  initSent         [label="InitSent"];
  responseSent     [label="ResponseSent"];
  activeInitiator  [label="Active (Initiator)"];
  activeResponder  [label="Active (Responder)"];
  expired          [shape=Msquare, label="Expired"];
    
  idle -> initSent
    [label="⊥ / hs_initiation"];
    
  initSent -> initSent
    [label="cookie_reply / hs_initiation(mac2)"];
    
  initSent -> initSent
    [label="hs_response / cookie_reply" color="red"];

  initSent -> activeInitiator
    [label="hs_response / transport_data"];

  idle -> responseSent
    [label="hs_initiation / hs_response"];

  idle -> idle
    [label="hs_initiation / cookie_reply" color="red"];

  responseSent -> activeResponder
    [label="transport_data / ⊥"];

  responseSent -> responseSent
    [label="cookie_reply / hs_response(mac2)"];
    
  activeInitiator -> activeInitiator
      [label="transport_data / ⊥"];
  activeInitiator -> activeInitiator
      [label="⊥ / transport_data"];
      
  activeResponder -> activeResponder
      [label="transport_data / ⊥"];
  activeResponder -> activeResponder
      [label="⊥ / transport_data"];

  initSent -> expired
    [label="expiration"];

  responseSent -> expired
    [label="expiration"];

  activeInitiator -> expired
    [label="expiration"];

  activeResponder -> expired
    [label="expiration"];
 
}
```