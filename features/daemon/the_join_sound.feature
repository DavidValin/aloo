@US-038
Feature: Hearing when someone arrives where your voice is pointed

  As someone with aloo connected in the background
  I want a sound when somebody turns up where my voice is currently going
  So that I know there is a reason to hold the shortcut, without looking

  The sound is narrow on purpose. It exists for one situation: nobody is
  looking at aloo, and something changed where a held shortcut would land.
  Anything wider is noise - a foreground client already shows the arrival
  in its log, an attached terminal already has it on screen, and a channel
  you are not pointed at is not somewhere your next words are going.

  It follows the *current* focus, not the --initial-focus the daemon was started
  with. The two agree until someone attaches and moves; after that only the
  live one is worth announcing, since that is where the shortcut goes.

  See docs/SPEC.md, "Running in background mode".

  @AC-204
  Scenario: Someone joining the focused channel is announced
    Given aloo is running in the background with nobody watching
    And the focus is on the channel "ops"
    When the daemon is told bob joined "ops"
    Then the join sound plays

  @AC-204
  Scenario: Every arrival in the focused channel is its own event
    Given aloo is running in the background with nobody watching
    And the focus is on the channel "ops"
    When the daemon is told bob joined "ops"
    And the daemon is told carol joined "ops"
    Then the join sound has played 2 times in total

  @AC-204
  Scenario: A channel you are not pointed at stays silent
    Given aloo is running in the background with nobody watching
    And the focus is on the channel "ops"
    When the daemon is told bob joined "team"
    Then the join sound does not play

  # The focus followed here is the live one. Someone who attached, moved to
  # another channel and detached again is pointed somewhere new, and that is
  # what the sound tracks - not the flag the daemon booted with.
  @AC-204
  Scenario: The sound follows the focus wherever it was moved to
    Given aloo is running in the background with nobody watching
    And the focus is on the channel "team"
    When the daemon is told bob joined "team"
    Then the join sound plays

  @AC-204
  Scenario: The focused person coming online is announced
    Given aloo is running in the background with nobody watching
    And the focus is on a private conversation with bob
    When the daemon is told bob joined "ops"
    Then the join sound plays

  # A peer joining two channels you share produces two UserJoined, but
  # "bob is online" is one event however many rooms it arrives through.
  @AC-204
  Scenario: Coming online is announced once, however many channels it arrives through
    Given aloo is running in the background with nobody watching
    And the focus is on a private conversation with bob
    When the daemon is told bob joined "ops"
    And the daemon is told bob joined "team"
    Then the join sound has played 1 time in total

  @AC-204
  Scenario: Coming back online later is announced again
    Given aloo is running in the background with nobody watching
    And the focus is on a private conversation with bob
    When the daemon is told bob joined "ops"
    And the daemon is told bob went offline
    And the daemon is told bob joined "ops"
    Then the join sound has played 2 times in total

  @AC-204
  Scenario: Somebody other than the focused person stays silent
    Given aloo is running in the background with nobody watching
    And the focus is on a private conversation with bob
    When the daemon is told carol joined "ops"
    Then the join sound does not play

  # While a terminal is watching, the arrival is already on screen.
  @AC-204
  Scenario: Nothing is announced out loud while someone is watching
    Given aloo is running in the background with nobody watching
    And a terminal is attached and watching
    And the focus is on the channel "ops"
    When the daemon is told bob joined "ops"
    Then the join sound does not play

  @AC-204
  Scenario: A foreground client never plays it
    Given aloo is running in the foreground
    And the focus is on the channel "ops"
    When the daemon is told bob joined "ops"
    Then the join sound does not play

  @AC-204
  Scenario: With nothing focused there is nothing to announce
    Given aloo is running in the background with nobody watching
    And nothing is focused yet
    When the daemon is told bob joined "ops"
    Then the join sound does not play
