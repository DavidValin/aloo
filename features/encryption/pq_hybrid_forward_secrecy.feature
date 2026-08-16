@US-028
Feature: Losing a key today does not expose what was said yesterday

  As a user of the quantum-resistant identity
  I want the keys that unlock my messages to be thrown away as I go
  So that someone who later steals my keybundle still cannot read what I already said

  A pq_hybrid identity is two halves. The signing half lives in the
  keybundle file and never changes - it is what proves who you are, and what
  your contacts pin. The encryption half moves: it is regenerated per
  contact as messages go back and forth, and each superseded key is
  destroyed. Stealing the file gets an attacker your name, not your history.

  The one exception is the very first message of a relationship, before
  either side has rotated. That one is encrypted to the bootstrap key the
  keybundle does hold, so it is not covered - which is why rotation starts
  with the first message exchanged. See docs/PROTOCOL.md.

  @AC-116
  Scenario: A message still reaches its recipient after keys have rotated
    Given alice and bob each have a pq_hybrid identity
    And bob has rotated his encryption keys
    When alice seals "after rotating" for bob using his current key
    Then bob reads back exactly what was sealed

  @AC-117
  Scenario: A stolen keybundle does not open yesterday's message
    Given alice and bob each have a pq_hybrid identity
    And bob has rotated his encryption keys
    When alice seals "yesterday's secret" for bob using his current key
    And bob rotates past that key enough times for it to be forgotten
    Then bob's own keybundle file cannot open that message any more

  @AC-118
  Scenario: A rotation is only trusted if the identity itself signed it
    Given alice and bob each have a pq_hybrid identity
    When alice offers bob a fresh encryption key signed by her identity
    Then bob trusts it and encrypts to the new key
    But a rotation signed by somebody else is refused

  @AC-119
  Scenario: A rotation names who it is for
    Given alice and bob each have a pq_hybrid identity
    And carol also has a pq_hybrid identity
    When alice offers bob a fresh encryption key signed by her identity
    Then carol cannot use that same rotation as if it were meant for her

  @TB-164
  Scenario: A few recent keys are kept so a burst of messages still opens
    Given alice and bob each have a pq_hybrid identity
    When alice seals 3 messages for bob under the same key
    And bob rotates once
    Then bob can still open all 3
