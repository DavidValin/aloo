@US-002
Feature: Gating who may connect to the server

  As a server operator
  I want to gate who may connect, by shared password or RSA keypair
  So that only clients I have authorised can join

  The server is started in exactly one of three auth modes and advertises
  which in its opening Hello; a client must answer with the matching kind.
  See docs/PROTOCOL.md section 5.

  @AC-013
  Scenario: The right password gets in
    Given a server that requires the password "s3cret"
    When a client offers the password "s3cret"
    Then the connection is accepted

  @AC-013
  Scenario: The wrong password does not
    Given a server that requires the password "s3cret"
    When a client offers the password "wrong"
    Then the connection is refused

  @AC-013 @TB-013 @TB-014 @TB-016
  Scenario: Only the holder of the server's key can answer its challenge
    Then an RSA-protected server accepts the real key holder and refuses an impostor

  @AC-014 @TB-013 @TB-014
  Scenario: An open server lets anyone in without a credential
    Then an open server issues no challenge and accepts an empty credential
