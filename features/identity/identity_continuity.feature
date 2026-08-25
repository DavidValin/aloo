@US-029
Feature: Proving an identity is still the same one

  As a user who has talked to someone before
  I want a planned key change to prove itself, and a real one to be verifiable
  So that the warning I get means something when it finally appears

  Pinning alone can only say "these bytes differ from last time". It cannot
  tell a friend who regenerated their keys from a stranger who took their
  nickname, so it asks the user about both - and a warning that fires for
  harmless reasons teaches people to dismiss it.

  Three things close that. A pin can be marked *verified* once the two of
  you have compared a safety phrase. A planned key change can carry a
  continuity certificate, signed by the keys being retired, which re-pins
  silently instead of raising an alarm. And an identity card, shared any way
  you like, pins someone as verified before you have ever spoken. See
  docs/PROTOCOL.md.

  @AC-120 @pqhybrid
  Scenario: The same identity always reads out the same safety phrase
    Given alice has a pq_hybrid identity
    Then alice's safety phrase is the same every time it is read
    And a different identity reads out a different phrase

  @AC-121 @pqhybrid
  Scenario: A pin can be raised from trusted-on-sight to verified
    Given a local identity store with nothing pinned yet
    When alice is seen with the key "key-a"
    Then alice is pinned but not yet verified
    When alice's key is confirmed out of band
    Then alice is pinned and verified

  @AC-122 @pqhybrid @with_server @without_reachable_server
  Scenario: A planned key change proves itself and raises no alarm
    Given alice has a pq_hybrid identity
    And alice is pinned under that identity
    When alice retires those keys for new ones, carrying a continuity certificate
    Then the new identity proves it is still alice
    And the pin moves to the new identity without asking

  @AC-122 @pqhybrid @with_server @without_reachable_server
  Scenario: A continuity certificate still proves itself when the new identity arrives from a different device
    Given alice has a pq_hybrid identity
    And alice is pinned on device "laptop" under that identity
    When alice retires those keys for new ones, carrying a continuity certificate
    And the new identity connects from device "phone"
    Then the new identity proves it is still alice
    And the pin moves to device "phone" without asking
    And device "laptop" no longer has an entry

  @AC-123 @pqhybrid
  Scenario: A stranger taking the nickname cannot fake continuity
    Given alice has a pq_hybrid identity
    And alice is pinned under that identity
    When a stranger takes alice's nickname with an unrelated identity
    Then the stranger cannot prove continuity
    And the pin is left exactly as it was

  @AC-124 @pqhybrid
  Scenario: An identity card pins someone before you ever speak
    Given alice has a pq_hybrid identity
    When alice exports an identity card
    And bob imports that card
    Then bob has alice pinned and verified without having met her

  @AC-125 @pqhybrid
  Scenario: A tampered identity card is refused
    Given alice has a pq_hybrid identity
    When alice exports an identity card
    And that card is altered in transit
    And bob imports that card
    Then bob refuses to import it
