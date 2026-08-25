@US-051
Feature: Channel moderation

  As the admin of a channel I created
  I want to delete it, ban or unban a member, control who may join, or
  hand off admin to someone else
  So that I can keep the channel I started under control

  See docs/PROTOCOL.md section 6.7.

  @AC-340
  Scenario: The admin deletes the public channel they created, and it can be recreated
    Given a running server registry
    And alice and bob are registered users
    When alice creates the public channel "general"
    And bob joins the public channel "general"
    And alice tries to delete "general"
    Then bob is told "general" was removed
    When bob creates the public channel "general"
    Then bob is confirmed as the admin of "general"

  @AC-340
  Scenario: Deleting a channel you do not administer is refused
    Given a running server registry
    And alice and bob are registered users
    When alice creates the public channel "general"
    And bob tries to delete "general"
    Then the attempt is refused, naming "admin"

  @AC-340
  Scenario: Deleting a private channel is refused, even for its own admin
    Given a running server registry
    And alice and bob are registered users
    When alice creates the private channel "secret-room"
    And alice tries to delete "secret-room"
    Then the attempt is refused, naming "public"

  @AC-341 @TB-258
  Scenario: A ban forces removal and blocks future joins, until unbanned
    Given a running server registry
    And alice and bob are registered users
    When alice creates the public channel "general"
    And bob joins the public channel "general"
    And alice bans bob from "general"
    Then bob is told they were banned from "general"
    And bob's next attempt to join "general" is refused as banned
    When alice unbans bob from "general"
    Then bob can join "general"

  @AC-341
  Scenario: Banning from a channel you do not administer is refused
    Given a running server registry
    And alice and bob are registered users
    When alice creates the public channel "general"
    And bob bans alice from "general"
    Then the attempt is refused, naming "admin"

  @AC-342 @TB-259
  Scenario: Locking joins refuses everyone off the list, and "all users" reopens it
    Given a running server registry
    And alice and bob are registered users
    When alice creates the public channel "general"
    And alice locks "general" to just carol
    Then bob's attempt to join "general" is refused, not being on the list
    When alice opens "general" back up to all users
    Then bob can join "general"

  @AC-343
  Scenario: Assigning admin requires membership first, then hands off admin rights
    Given a running server registry
    And alice and bob are registered users
    When alice creates the public channel "general"
    And alice assigns admin of "general" to bob
    Then the attempt is refused, naming "member"
    When bob joins the public channel "general"
    And alice assigns admin of "general" to bob
    Then bob becomes the new admin of "general"
    When alice tries to delete "general"
    Then the attempt is refused, naming "admin"
    When bob tries to delete "general"
    Then bob is told "general" was removed
