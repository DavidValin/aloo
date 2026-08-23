@US-046
Feature: Stopping an unproven direct-punch requester from turning into free guessing

  As someone running direct punching with no server involved
  I want a source that keeps failing to prove any identity to be permanently blocked
  So that an attacker cannot use my fixed punch port as a free oracle for guessing which of my pinned keys matches a name they invented

  Every genuine failed check (docs/PROTOCOL.md 7.1.5's unknown-nickname flow:
  the user agreed to check, the scan ran, nothing matched) against one source
  IP is a strike. Three strikes, spanning at least two different clock
  minutes, within a rolling 10-hour window, bans that IP outright: no further
  direct-punch request from it is even shown a popup, and the ban survives a
  restart. See ~/.aloo/banned_ips.log.

  @AC-280
  Scenario: Three failed checks spanning two clock minutes bans the source
    Given a fresh ban list
    When a source has two genuine failed checks a minute apart
    And that same source has one more genuine failed check right after
    Then that source is banned

  @AC-280
  Scenario: Three failed checks crammed into the same minute do not ban
    Given a fresh ban list
    When a source has three genuine failed checks all within the same minute
    Then that source is not banned

  @AC-280
  Scenario: Failed checks older than the rolling window are forgotten
    Given a fresh ban list
    When a source had two genuine failed checks over ten hours ago
    And that same source has one genuine failed check now
    Then that source is not banned

  @AC-281
  Scenario: A banned source cannot be checked again to shake off the ban
    Given a fresh ban list
    And a source is already banned
    When that source is asked for one more failed check
    Then that source is still banned
    And no fresh strike is counted against it

  @AC-282
  Scenario: A ban outlives the process that recorded it
    Given a fresh ban list
    And a source has just been banned
    When the ban list is reloaded from disk
    Then that source is still banned

  @AC-282 @TB-248
  Scenario: The file names how many sources are banned, recomputed each time
    Given a fresh ban list
    When two different sources are each banned
    Then the ban list file's header reads "2 banned"

  @TB-248
  Scenario: Removing a line by hand lifts that ban immediately
    Given a fresh ban list
    And a source has just been banned
    When that source's line is deleted from the file by hand
    And the ban list is reloaded from disk
    Then that source is no longer banned

  @TB-248
  Scenario: A corrupted line in the file is skipped, not fatal
    Given a ban list file with one good line and one unparseable line
    When the ban list is reloaded from disk
    Then the source named on the good line is still banned
