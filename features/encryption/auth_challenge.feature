@US-008
Feature: RSA-OAEP is sound on its own

  As a user relying on pq_hybrid's RSA-4096 hedge against a flawed
  post-quantum primitive
  I want RSA-OAEP encryption itself to be sound - readable only by the
  intended key
  So that the classical half of the hedge is trustworthy independent of
  the post-quantum half

  This file is about RSA-OAEP itself, chunked per docs/PROTOCOL.md section
  8.1 - the primitive pq_hybrid's RSA-4096 hedge (section 13.5) is built
  on. Server login is a nickname and its password (section 5.1), not any
  RSA challenge. RSA-OAEP is not how peer-to-peer message content is
  encrypted either - nothing there uses it directly. That is
  features/encryption/message_encryption.feature, which covers all three
  layerings a message can travel under.

  @AC-040
  Scenario: A payload can be read only by the holder of the key it was encrypted for
    Given alice and bob each have their own RSA keypair
    When the message "meet me at six" is encrypted for alice
    Then alice reads back exactly what was sent
    And bob cannot read it at all

  @AC-041 @TB-051
  Scenario: A payload longer than one RSA block is split and put back together
    Given alice and bob each have their own RSA keypair
    When a message spanning more than two RSA blocks is encrypted for alice
    Then it was split into at least 3 separately encrypted blocks
    And alice reads back exactly what was sent

  @AC-041 @TB-052
  Scenario: An empty payload is still encrypted rather than sent as nothing
    Given alice and bob each have their own RSA keypair
    When an empty message is encrypted for alice
    Then it produced exactly 1 encrypted block
    And alice reads back exactly what was sent

  @TB-057
  Scenario: A key can be recognised later by its fingerprint
    Given alice and bob each have their own RSA keypair
    Then a fingerprint of the key is stable and distinguishes it from any other key
