@US-004
Feature: Joining and leaving channels

  As a connected user
  I want to move between the server's channels and open private ones by name
  So that I can take part in the conversation I care about

  Joining is also how peers learn each other's public keys: the membership
  snapshot a joiner receives carries every existing member's key, which is
  what makes it possible to encrypt to them at all.
  See docs/PROTOCOL.md section 6.

  @AC-018
  Scenario: A freshly started server always has somewhere to talk
    Given a running server registry
    Then a brand new server offers exactly one public channel called "general"

  @AC-019 @TB-022
  Scenario: Joining introduces the newcomer and the room to each other
    Given a server that anyone may connect to
    And alice has connected
    And bob has connected
    When alice joins the channel "general"
    Then alice is confirmed as joined
    When bob joins the channel "general"
    Then bob learns about "alice" and then that the join succeeded
    And alice is told that "bob" joined

  @AC-022
  Scenario: A private channel is never advertised to anyone
    Given a running server registry
    And alice and bob are registered users
    Then alice joining the private channel "secret-room" leaves it unlisted

  @AC-023 @TB-102
  Scenario: Leaving one channel tells the people still in it
    Given a running server registry
    And alice and bob are registered users
    And alice and bob have both joined "general"
    When alice leaves "general"
    Then bob is told that alice left "general"
    And alice is still connected
