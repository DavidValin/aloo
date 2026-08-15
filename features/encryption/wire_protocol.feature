@US-009
Feature: Carrying every protocol message intact over the wire

  As a client or server implementation
  I want every protocol message to survive framing, encoding and decoding
  So that two peers built from the same definitions interoperate

  The payload format is schema-less (bincode), so nothing on the wire
  identifies which type produced it - a decoder must already know the exact
  expected shape. That makes round-trip fidelity a correctness property
  rather than a convenience. See docs/PROTOCOL.md sections 2 and 9.

  @AC-043 @TB-060
  Scenario: Every kind of message survives the trip to the wire and back
    When every kind of protocol message is written to the wire and read back
    Then every field arrives exactly as it was sent

  @TB-061
  Scenario: A user's announced key mode is carried faithfully
    Then a user announced under any key mode arrives with that same key mode
