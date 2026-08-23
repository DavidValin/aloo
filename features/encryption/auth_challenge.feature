@US-008
Feature: Proving to a server that you hold its key

  As a server operator who handed out an rsa key
  I want a connecting client to prove it holds that key before it is let in
  So that only clients I have authorised can join

  This file is about RSA-OAEP, which serves exactly one purpose in this
  app: the server's `rsa` auth challenge, where the client proves itself by
  decrypting a nonce (docs/PROTOCOL.md section 5.3), chunked per section
  8.1. It is *not* how messages are encrypted - nothing peer-to-peer uses
  it. That is features/encryption/message_encryption.feature, which covers
  all three layerings a message can travel under.

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
