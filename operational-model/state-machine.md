# Notes

- Cookie reply in initSent state are not (explicitly) described in the spec. There should be no explicit retransmissions when receiving a cookie reply?
- How do we handle receiving multiple handshake initiation messages, e.g., in the `ResponseSent` phase or `InitSent` phase? What if we're under load?

# State Machine

```
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
```