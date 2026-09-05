Feature: How a message is encrypted, at every layer

  As a user of an end-to-end encrypted chat
  I want to know exactly what protects each thing I send
  So that "encrypted" is a specific claim rather than a reassuring word

  Everything peer-to-peer travels under one of three layerings, and every
  scenario below carries a tag naming the one it exercises. Run just one
  of them with, say, `cargo bdd -- -t "@direct_otp"`.

  pqhybrid - a sealed send and nothing more. ML-DSA-87+RSA-4096 sign it,
  ML-KEM-1024+X25519 wrap a per-send key, AES-256-GCM encrypts the
  content. Bound to one recipient and one room, refused if replayed.
  docs/PROTOCOL.md section 13.

  pqhybrid_otp - a one-time pad on the message, with that same sealed
  envelope built *around* the pad: seal(pad(payload)). The envelope's
  signature and the pad's own decrypt verdict both apply. Sealing outermost
  is what keeps the pad's cost to the length of the message rather than the
  ~6.4KB an envelope weighs, and lets a forgery be refused before any pad
  is spent; what it costs is that the seal's binding is the outermost
  layer, so an OTP send carries no room name and no recipient fingerprint
  in it. Section 16.2's PqWrapped framing.

  direct_otp - a one-time pad and nothing around it: pad(payload), for a
  pair who reach each other peer-to-peer and have never exchanged
  keybundles: no server, or one that never introduced them. There is
  nothing to seal an envelope to, and nothing is given up - the pad is the
  protection, and the otp command refusing anything it cannot attribute to
  the holder of the mirror key at the expected offset is the
  authentication. Section 16.2's Direct framing.

  otp_control - a fourth tag, marking the scenarios about turning the pad
  layer on and off and showing it on screen. Those hold identically under
  either pad framing, which is why they name neither.

  The file spans three user stories, so each scenario carries its own
  US- tag rather than inheriting one.

  Every one-time-pad operation shells out to the real `otp` command
  (github.com/DavidValin/otp-toolkit) - aloo contains no pad cryptography
  or keychain-format code of its own. The full framing matrix over every
  content type (text, a file's two spends, a voice message, each under all
  three layerings) is proven in the Rust layer, in
  test/otp_ack_wiring_test.rs.

  # -------------------------------------------------------------------
  # @pqhybrid - a sealed send, with no pad inside it
  #
  # One sealed layout covers every kind of content: one setup naming who
  # the content is for and which room it belongs to, signed by the sender,
  # plus the content itself under a key only that setup unlocks. Text is
  # simply a send with one chunk.
  # -------------------------------------------------------------------

  @US-027 @AC-111 @pqhybrid
  Scenario: A sealed message reaches the person it was sealed for
    Given alice and bob each have a pq_hybrid identity
    When alice seals "meet me at six" for bob
    Then bob reads back exactly what was sealed

  @US-027 @AC-112 @pqhybrid
  Scenario: A message sealed for someone else is refused
    Given alice and bob each have a pq_hybrid identity
    And carol also has a pq_hybrid identity
    When alice seals "meet me at six" for bob
    And carol is handed that very same sealed message
    Then carol refuses it

  @US-027 @AC-113 @pqhybrid
  Scenario: A private message replayed into a channel is refused
    Given alice and bob each have a pq_hybrid identity
    When alice seals "meet me at six" for bob privately
    And that sealed message is presented as if it belonged to the channel "the-hall"
    Then bob refuses it

  @US-027 @AC-114 @pqhybrid
  Scenario: A message that already arrived once is refused the second time
    Given alice and bob each have a pq_hybrid identity
    When alice seals "meet me at six" for bob
    And bob accepts it
    And the very same sealed message arrives again
    Then bob refuses it

  @US-027 @AC-114 @AC-420 @pqhybrid
  Scenario: A queued message that arrives after newer ones is not mistaken for a replay
    Given alice and bob each have a pq_hybrid identity
    When alice seals "while you were out" for bob with send id 7
    And it waits undelivered while 3 newer sends reach bob
    And it is finally delivered
    Then bob accepts it
    And bob reads back exactly what was sealed

  @US-027 @AC-115 @TB-160 @pqhybrid
  Scenario: Streamed content is sealed exactly like a text message
    Given alice and bob each have a pq_hybrid identity
    When alice seals a stream of 3 chunks for bob
    Then bob reads back every chunk in that stream
    And the stream's setup is what proved the sender, before any chunk was accepted

  @US-027 @TB-161 @pqhybrid
  Scenario: Two chunks of one send never repeat a nonce
    Given alice and bob each have a pq_hybrid identity
    When alice seals a stream of 3 chunks for bob
    Then no two chunks of that stream are byte-identical

  # -------------------------------------------------------------------
  # @pqhybrid - and the keys that unlock it are thrown away as you go
  #
  # A pq_hybrid identity is two halves. The signing half lives in the
  # keybundle file and never changes - it is what proves who you are, and
  # what your contacts pin. The encryption half moves: regenerated per
  # contact as messages go back and forth, each superseded key destroyed.
  # Stealing the file gets an attacker your name, not your history.
  #
  # The one exception is the very first message of a relationship, before
  # either side has rotated. That one is encrypted to the bootstrap key the
  # keybundle does hold, which is why rotation starts with the first
  # message exchanged.
  # -------------------------------------------------------------------

  @US-028 @AC-116 @pqhybrid
  Scenario: A message still reaches its recipient after keys have rotated
    Given alice and bob each have a pq_hybrid identity
    And bob has rotated his encryption keys
    When alice seals "after rotating" for bob using his current key
    Then bob reads back exactly what was sealed

  @US-028 @AC-117 @pqhybrid
  Scenario: A stolen keybundle does not open yesterday's message
    Given alice and bob each have a pq_hybrid identity
    And bob has rotated his encryption keys
    When alice seals "yesterday's secret" for bob using his current key
    And bob rotates past that key enough times for it to be forgotten
    Then bob's own keybundle file cannot open that message any more

  @US-028 @AC-118 @pqhybrid
  Scenario: A rotation is only trusted if the identity itself signed it
    Given alice and bob each have a pq_hybrid identity
    When alice offers bob a fresh encryption key signed by her identity
    Then bob trusts it and encrypts to the new key
    But a rotation signed by somebody else is refused

  @US-028 @AC-119 @pqhybrid
  Scenario: A rotation names who it is for
    Given alice and bob each have a pq_hybrid identity
    And carol also has a pq_hybrid identity
    When alice offers bob a fresh encryption key signed by her identity
    Then carol cannot use that same rotation as if it were meant for her

  @US-028 @TB-164 @pqhybrid
  Scenario: A few recent keys are kept so a burst of messages still opens
    Given alice and bob each have a pq_hybrid identity
    When alice seals 3 messages for bob under the same key
    And bob rotates once
    Then bob can still open all 3

  # -------------------------------------------------------------------
  # @pqhybrid_otp - a pad on the message, sealed inside an envelope
  #
  # Both sides hold a pq_hybrid identity, so the pad goes on the message
  # and an envelope is sealed around the pad. Both protections apply at
  # once, and the pad pays for the message rather than for the envelope.
  # -------------------------------------------------------------------

  @US-033 @AC-136 @pqhybrid_otp
  Scenario: Both sides converge on the same otp contact name for each other
    Given alice and bob each have a pq_hybrid identity
    Then alice and bob compute the very same otp contact name for each other

  @US-033 @AC-136 @AC-260 @pqhybrid_otp
  Scenario: The pad goes on the message and the seal goes around the pad
    Given alice and bob each have a pq_hybrid identity
    And alice and bob have provisioned an otp contact for each other
    When alice pads "meet me at six" for bob and seals the pad
    Then the pad only ever covered the message, never the seal around it
    And bob opens the seal, unwraps the pad, and reads back exactly what was sent

  @US-033 @AC-260 @pqhybrid_otp
  Scenario: The outermost layer names neither its recipient nor its room
    Given alice and bob each have a pq_hybrid identity
    And alice and bob have provisioned an otp contact for each other
    When alice pads "meet me at six" for bob and seals the pad
    Then the sealed bytes name neither their recipient nor a room
    And bob opens the seal, unwraps the pad, and reads back exactly what was sent

  @US-033 @AC-250 @pqhybrid_otp
  Scenario: The two sides derive the same acknowledgement proof independently
    Given alice and bob each have a pq_hybrid identity
    And alice and bob have provisioned an otp contact for each other
    When alice pads "meet me at six" for bob and seals the pad
    Then bob opens the seal, unwraps the pad, and reads back exactly what was sent
    And the acknowledgement proof the receiver computed matches the sender's

  @US-033 @AC-137 @pqhybrid_otp
  Scenario: A second message under the pad waits for a genuine delivery acknowledgement
    Given alice and bob each have a pq_hybrid identity
    And alice and bob have provisioned an otp contact for each other
    When alice sends "first" to bob under the pad
    Then "first" was sent immediately
    When alice sends "second" to bob under the pad
    Then "second" is held back, not sent
    When bob's delivery ack for "first" arrives
    Then the held message "second" is sent

  # A pad is a sequence, not a set: every position is read exactly once and
  # strictly in turn. Both halves matter - a repeat must not reach the pad
  # a second time (it would be read with the wrong bytes and would spend
  # what cannot be replaced), and it must not be met with silence either,
  # since the sender's gate only ever opens on an acknowledgement.
  @US-033 @AC-304 @pqhybrid_otp
  Scenario: A pad message that arrives twice is answered from the record, never from the pad
    Given alice and bob each have a pq_hybrid identity
    And alice and bob have provisioned an otp contact for each other
    When bob accepts the padded message at sequence 0
    Then the padded message at sequence 0 is not let near the pad again
    And bob answers it with the acknowledgement he already recorded

  @US-033 @AC-304 @pqhybrid_otp
  Scenario: Padded messages are read in the order they were sealed, never out of turn
    Given alice and bob each have a pq_hybrid identity
    And alice and bob have provisioned an otp contact for each other
    Then the padded message at sequence 0 is the one it will read next
    And the padded message at sequence 1 is refused as out of turn
    When bob accepts the padded message at sequence 0
    Then the padded message at sequence 1 is the one it will read next
    And the padded message at sequence 0 is refused as out of turn

  @US-033 @TB-186 @pqhybrid_otp
  Scenario: A pad far larger than one network datagram still arrives whole
    Given alice generates a fresh 2MB pad for bob
    When it is sent to bob in many small pieces
    Then bob's reassembled pad is byte-identical to the one alice generated

  @US-033 @AC-142 @pqhybrid_otp
  Scenario: An invitation that is never accepted leaves nothing behind
    Given alice and bob each have a pq_hybrid identity
    When alice generates a pad for bob that bob never accepts
    Then alice holds no otp contact for bob
    And a later invitation from alice to bob still succeeds

  @US-033 @AC-142 @pqhybrid_otp
  Scenario: A refused invitation does not block the next one
    Given alice and bob each have a pq_hybrid identity
    When alice generates a pad for bob that bob refuses
    Then alice holds no otp contact for bob
    And a later invitation from alice to bob still succeeds

  @US-033 @AC-142 @pqhybrid_otp
  Scenario: A refused invitation does not block one going the other way
    Given alice and bob each have a pq_hybrid identity
    When alice generates a pad for bob that bob refuses
    Then a later invitation from bob to alice still succeeds

  @US-033 @AC-142 @pqhybrid_otp
  Scenario: A pad owed to a peer is re-offered unchanged rather than regenerated
    Given alice and bob each have a pq_hybrid identity
    When alice generates a pad for bob that bob never accepts
    Then the pad alice would re-send is byte-identical to the one she generated

  @US-033 @AC-142 @pqhybrid_otp
  Scenario: Both users invite each other at once and only one pad survives
    Given alice and bob each have a pq_hybrid identity
    When alice and bob both generate a pad for each other before either answers
    Then both sides agree on which pad survives
    And the conceding side keeps no pad of its own

  # -------------------------------------------------------------------
  # @direct_otp - a pad, with no envelope around it
  #
  # Neither side can read the other as a keybundle, so no envelope can be
  # built and none is needed. This is the pairing that works with no server
  # at all - and the one where the pad, rather than a signature, is what
  # says who is speaking.
  # -------------------------------------------------------------------

  @US-033 @AC-259 @AC-082 @direct_otp
  Scenario: Two peers with a pad and no keybundles talk anyway
    Given alice and bob reach each other directly and hold a pad for each other
    And neither of them has ever learned the other's keybundle
    Then their pair is framed direct, with no envelope around the pad
    And each of them files the pad under the very same contact name
    When alice's link to bob comes up
    Then bob is registered from the pad alone, with otp already active
    When alice sends bob "no server, no keybundle, still private"
    Then bob reads it, and registers alice because the pad opened it
    And bob's acknowledgement proves he decrypted it

  @US-033 @AC-381 @direct_otp
  Scenario: Deleting a key with no active session shows no ended notice
    Given alice and bob reach each other directly and hold a pad for each other
    And alice and bob are both registered, with otp active
    When alice deletes the otp key for bob
    Then alice no longer shows an active otp session with bob
    And bob still shows an active otp session with alice

  @US-033 @AC-381 @direct_otp
  Scenario: Deleting an active session's own key ends it locally, not just the keychain
    Given alice and bob reach each other directly and hold a pad for each other
    And alice and bob are both registered, with otp active
    When bob deletes the otp key for alice
    Then bob no longer shows an active otp session with alice
    And bob's otp status notice says "ended"

  @US-033 @AC-380 @direct_otp
  Scenario: A message decrypts normally while both sides still hold the key
    Given alice and bob reach each other directly and hold a pad for each other
    And alice and bob are both registered, with otp active
    When alice sends bob "still shared, still readable"
    Then bob decrypts it normally and the session stays active for both

  @US-033 @AC-380 @direct_otp
  Scenario: A message the recipient can no longer decrypt ends his own side of the session
    Given alice and bob reach each other directly and hold a pad for each other
    And alice and bob are both registered, with otp active
    And bob's otp keychain entry for alice is gone, without the app knowing yet
    When alice sends bob "are you still there"
    Then bob cannot decrypt it, and ends his own side of the session
    And bob's otp status notice says "ending the session"

  @US-033 @AC-259 @direct_otp
  Scenario: A pad-only pair needs no /otp round trip to start
    Given alice and bob reach each other directly and hold a pad for each other
    When alice runs /otp with bob
    Then otp is active for bob immediately, with nothing sent to negotiate it

  @US-033 @AC-260 @AC-310 @direct_otp
  Scenario: Ending a session travels under the pad it is ending
    Given alice and bob reach each other directly and hold a pad for each other
    When alice runs /endotp with bob
    Then the notice reaches bob under the pad, and his proof-carrying ack settles it

  @US-033 @AC-310 @direct_otp
  Scenario: Ending needs the peer reachable, and a refusal spends nothing
    Given alice and bob reach each other directly and hold a pad for each other
    And bob has become unreachable for alice
    When alice runs /endotp with bob expecting a refusal
    Then the end is refused with nothing spent and the session still active

  @US-033 @AC-307 @direct_otp
  Scenario: An unconfirmed end notice is recovered on reconnect, never re-encrypted
    Given alice and bob reach each other directly and hold a pad for each other
    When alice runs /endotp with bob
    And bob drops before confirming, and later reconnects
    Then the very same notice is re-sent from recovery, and his confirmation ends it for both

  # A confirmed end is a durable fact of the contact, not of the connection
  # that carried it: neither side coming back, nor an app restart, may
  # switch it back on for one side only. Only /otp does, on both sides.
  @US-033 @AC-443 @direct_otp
  Scenario: A confirmed end stays ended across a restart
    Given alice and bob reach each other directly and hold a pad for each other
    When alice runs /endotp with bob
    And bob confirms the end
    And alice's app restarts and bob's link comes up again
    Then alice still shows the session with bob as ended
    When alice runs /otp with bob
    Then otp is active for bob immediately, with nothing sent to negotiate it

  @US-033 @AC-444 @direct_otp
  Scenario: Two ends crossing keep every spent position accounted for
    Given alice and bob reach each other directly and hold a pad for each other
    When alice runs /endotp with bob
    And bob runs /endotp with alice at the same moment
    And bob's notice reaches alice first
    Then alice's own notice keeps its slot, is re-sent from recovery, and bob's confirmation settles it

  @US-033 @AC-445 @direct_otp
  Scenario: An end asked for while sealed messages still wait goes out after them
    Given alice and bob reach each other directly and hold a pad for each other
    And queued sends are on for that pair
    When alice sends bob "one"
    And alice sends bob "two"
    And bob has acknowledged both, but alice's queue has not moved on from the second
    And alice runs /endotp with bob
    Then the end is owed, but nothing is spent on it while the queue still holds a message
    And once the queue drains, the notice goes out and ends it for both

  @US-033 @AC-316 @direct_otp
  Scenario: A voice recording survives the sender's own restart while awaiting acceptance
    Given alice and bob reach each other directly and hold a pad for each other
    When alice records and sends a voice message to bob
    And alice's whole process restarts before bob's acceptance is processed
    And alice reconnects and bob's acceptance reaches her
    Then the recording still reaches bob, byte-identical, with no pad spent twice

  # -------------------------------------------------------------------
  # @otp_control - turning the pad layer on and off, and marking it
  #
  # These are about the layer's own controls and what they put on screen.
  # They hold identically whether a seal goes around the pad or the pad
  # ciphertext travels alone, which is why none of them names a framing.
  # -------------------------------------------------------------------

  @US-033 @AC-138 @otp_control
  Scenario: A keychain contact provisioned outside the app is adopted, not regenerated
    Given alice has an otp contact for bob provisioned out of band
    When alice checks whether that contact can be adopted
    Then it is adopted without generating a fresh pad

  @US-033 @AC-139 @otp_control
  Scenario: A generate-confirm prompt must be answered before anything is generated or sent
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I am asked to generate a fresh otp pad for bob
    Then a prompt asks whether to generate and share a fresh pad with bob
    When I press Enter
    And I type "50"
    And I press Enter
    Then generating the pad was confirmed with a 50MB size

  @US-033 @AC-139 @otp_control
  Scenario: Declining the generate prompt cancels locally without sending anything
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I am asked to generate a fresh otp pad for bob
    And I press Right
    And I press Enter
    Then generating the pad was cancelled

  @US-033 @AC-139 @otp_control
  Scenario: An incoming invite names the sender and must be explicitly accepted
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob invites me to start an otp session
    Then an invite popup names bob
    When I press Enter
    Then the otp invite was accepted

  @US-033 @AC-139 @otp_control
  Scenario: Rejecting an incoming invite is also an explicit choice
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob invites me to start an otp session
    And I press Tab
    And I press Enter
    Then the otp invite was rejected

  @US-033 @AC-139 @otp_control
  Scenario: A second invite from a different sender waits its turn behind the first
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    When bob invites me to start an otp session
    And carol invites me to start an otp session
    Then an invite popup names bob
    When bob's invite is answered
    Then an invite popup names carol

  @US-033 @AC-139 @otp_control
  Scenario: The status notice announces whether a session started or was cancelled
    Given I am connected and viewing a channel
    Then no otp status notice is shown
    When an otp session started notice arrives
    Then an otp status notice says "OTP session started"
    When an otp session cancelled notice arrives
    Then an otp status notice says "OTP session cancelled"

  @US-033 @AC-140 @otp_control
  Scenario: An unrecognized slash command in a private room is never sent as text
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I type "/otpp" into the compose bar
    And I press Enter
    Then nothing happens
    And an otp status notice says "unknown command: /otpp"

  @US-033 @AC-243 @otp_control
  Scenario: A message details popup names the pad position it spent
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And the otp session with bob is active
    And bob's pad has sent 4 messages over 480 bytes and received 9 over 900
    And focus is on the compose
    When I type "under the pad"
    And I press Enter
    And I open the details of my last message
    Then the details name pad sequence 5 at offset 480
    And the details name the key file ending "_enc.key"

  @US-033 @AC-243 @otp_control
  Scenario: An arriving message names the receiving pad instead
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And the otp session with bob is active
    And bob's pad has sent 4 messages over 480 bytes and received 9 over 900
    When bob has sent me the private message "psst"
    And I open the details of my last message
    Then the details name pad sequence 10 at offset 900
    And the details name the key file ending "_dec.key"

  @US-033 @AC-246 @otp_control
  Scenario: A pad session marks that person wherever they are named
    Given I am connected and viewing a channel
    And bob is in the channel with me using pq_hybrid
    And carol is in the channel with me using pq_hybrid
    And I have opened a private room with bob
    And the otp session with bob is active
    Then bob carries the OTP tag on the DM selector
    When I press the [ key
    Then bob carries the OTP tag in the user list instead of their own
    And carol still carries their own tag

  # -------------------------------------------------------------------
  # @otp_control - ending a session with /endotp
  #
  # Ending pauses rather than destroys: this side's pad is kept, so a later
  # /otp with the same contact resumes it. The full send/receive/acknowledge
  # wiring (notifying the peer, retrying that notice on reconnect) needs a
  # live session and is verified manually with two clients
  # (docs/TESTING.md "Known coverage gaps") - these cover what is
  # observable at the compose bar and in local session state.
  # docs/PROTOCOL.md section 16.6.
  # -------------------------------------------------------------------

  @US-033 @AC-192 @otp_control
  Scenario: /endotp in an open private room ends the session
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And I have a direct connection to bob
    When I type "/endotp" into the compose bar
    And I press Enter
    Then the otp session was ended
    And the compose bar is empty

  @US-033 @AC-192 @otp_control
  Scenario: /endotp outside any private room does nothing
    Given I am connected and viewing a channel
    When I type "/endotp" into the compose bar
    And I press Enter
    Then nothing happens

  @US-033 @AC-310 @otp_control
  Scenario: /endotp is refused while the peer is offline
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has gone offline
    When I type "/endotp" into the compose bar
    Then the compose bar holds "/endotp"
    When I press Enter
    Then the end is refused because bob cannot confirm it

  @US-033 @AC-193 @otp_control
  Scenario: A disconnect alone does not end an active session
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the otp session with bob is active
    When bob goes offline
    Then the otp session with bob is still active
