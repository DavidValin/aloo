@US-011
Feature: A server introduction never disturbs an unrelated otp-only pin

  As a user who already reaches someone directly, pad-only, with no server
  I want a server later introducing us for real to pin cleanly alongside
  that, and a copied key to still be reviewed even under a brand-new device
  So that meeting the same person twice, two different ways, never collides
  and a copied identity file never silently walks in as if it were new

  A nickname's `pq_hybrid` pin and its `Direct`-framed (otp-only) pin are
  independent, non-colliding trust dimensions, scoped by `key_mode` - the
  crux fact behind the "Server introduces" reference table's rows 3-5. Row
  7 is the opposite edge: identical key bytes, pinned under a device that
  never itself proved it holds them, still requires a human to look. See
  docs/SPEC.md's reference table and docs/PROTOCOL.md section 12.

  @AC-047 @pqhybrid @direct_otp @with_server
  Scenario: A server introduces two peers who already hold an otp-only pin for each other
    Given alice already holds an otp-only pin for bob
    And bob already holds an otp-only pin for alice
    When a server introduces alice and bob with their real pq_hybrid identities
    Then alice now has two independent pins for bob: the otp-only one, untouched, and a fresh pq_hybrid one
    And bob now has two independent pins for alice: the otp-only one, untouched, and a fresh pq_hybrid one

  @AC-047 @pqhybrid @direct_otp @with_server
  Scenario: A server introduces two peers where only one already holds an otp-only pin for the other
    Given alice already holds an otp-only pin for bob
    And bob has nothing pinned for alice at all
    When a server introduces alice and bob with their real pq_hybrid identities
    Then alice now has two independent pins for bob: the otp-only one, untouched, and a fresh pq_hybrid one
    And bob has a plain first-sighting pq_hybrid pin for alice

  @AC-047 @pqhybrid @with_server
  Scenario: A server introduces two peers where only one already has the other pinned
    Given alice already has bob's real key pinned
    And bob has nothing pinned for alice at all
    When a server introduces alice and bob with their real pq_hybrid identities
    Then alice's pin for bob is an ordinary silent match
    And bob has a plain first-sighting pq_hybrid pin for alice

  @AC-048 @pqhybrid @with_server
  Scenario: An identical key already pinned under a different device still opens a review
    Given a local identity store with nothing pinned yet
    When alice is seen on device "d1" with the pq_hybrid key "key-a"
    And alice is seen on device "d2" with the pq_hybrid key "key-b"
    Then alice's device "d3" announcing the key "key-a" is not silently claimed
    When alice's device "d3" is accepted with the key "key-a"
    Then alice on device "d3" is pinned to the key "key-a"
    And alice on device "d1" is still pinned to the key "key-a"
    And alice on device "d2" is still pinned to the key "key-b"
