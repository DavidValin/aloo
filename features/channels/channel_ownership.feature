@US-051
Feature: Channel ownership

  As a user who creates a channel
  I want to be recognised as its owner
  So that a channel I start doesn't drift out of my control

  Every channel - public or private - belongs to whoever's join actually
  created it. The one permanent exception is "the-hall", which has no
  admin at all. See docs/PROTOCOL.md section 6.7.

  @AC-338
  Scenario: The creator of a public channel becomes its admin
    Given a running server registry
    And alice and bob are registered users
    When alice creates the public channel "general"
    Then alice is confirmed as the admin of "general"

  @AC-338
  Scenario: The creator of a private channel becomes its admin too
    Given a running server registry
    And alice and bob are registered users
    When alice creates the private channel "secret-room"
    Then alice is confirmed as the admin of "secret-room"

  @AC-338
  Scenario: The-hall has no admin
    Given a running server registry
    And alice and bob are registered users
    When alice joins the public channel "the-hall"
    Then "the-hall" has no admin

  @AC-338
  Scenario: A later joiner does not become admin
    Given a running server registry
    And alice and bob are registered users
    When alice creates the public channel "general"
    And bob joins the public channel "general"
    Then bob is told that alice administers "general"

  @AC-338 @AC-340
  Scenario: The-hall cannot be deleted, even by whoever tries
    Given a running server registry
    And alice and bob are registered users
    When alice joins the public channel "the-hall"
    And alice tries to delete "the-hall"
    Then the attempt is refused, naming "no admin"
