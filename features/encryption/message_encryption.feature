@US-008
Feature: Keeping message content readable only by its recipient

  As a user of an end-to-end encrypted chat
  I want every message encrypted separately for each recipient
  So that neither the server nor anyone else can read what I said

  Every my_key method except pq_hybrid (docs/PROTOCOL.md section 13) uses
  the same single algorithm - RSA-OAEP with SHA-256, applied once per
  recipient, no shared session key anywhere, so a message addressed to
  several people is genuinely several independent ciphertexts. See
  docs/PROTOCOL.md section 8.

  @AC-040
  Scenario: A message can be read only by the person it was encrypted for
    Given alice and bob each have their own RSA keypair
    When the message "meet me at six" is encrypted for alice
    Then alice reads back exactly what was sent
    And bob cannot read it at all

  @AC-041 @TB-051
  Scenario: A message longer than one RSA block is split and put back together
    Given alice and bob each have their own RSA keypair
    When a message spanning more than two RSA blocks is encrypted for alice
    Then it was split into at least 3 separately encrypted blocks
    And alice reads back exactly what was sent

  @AC-041 @TB-052
  Scenario: An empty message is still encrypted rather than sent as nothing
    Given alice and bob each have their own RSA keypair
    When an empty message is encrypted for alice
    Then it produced exactly 1 encrypted block
    And alice reads back exactly what was sent

  @AC-042
  Scenario: The same password rebuilds the same identity anywhere
    Given alice derives their identity from the password "hunter2"
    And bob derives their identity from the password "hunter2"
    Then alice and bob end up with the very same key

  @AC-042
  Scenario: Two different passwords never collide onto one identity
    Given alice derives their identity from the password "hunter2"
    And bob derives their identity from the password "correct horse battery staple"
    Then alice and bob end up with different keys

  @TB-057
  Scenario: A key can be recognised later by its fingerprint
    Given alice and bob each have their own RSA keypair
    Then a fingerprint of the key is stable and distinguishes it from any other key
