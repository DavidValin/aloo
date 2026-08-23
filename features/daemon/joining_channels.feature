@US-038
Feature: Which channels a daemon joins

  As someone running aloo in the background
  I want it in the channels I actually talk in
  So that a held shortcut reaches the people I meant

  A normal client joins `the-hall` the moment it connects. A daemon never
  does unless it is named, because the whole point of the mode is to be
  somewhere deliberate rather than somewhere default.

  See docs/SPEC.md "Running in background mode".

  @AC-202
  Scenario: It joins exactly what it was given, and nothing else
    Given no daemon settings and nothing in the connect cache
    When the daemon is started with --channels=team,ops
    Then it joins exactly "team, ops"
    And it does not join the-hall

  # Channels are separated by commas and a password follows its channel
  # after a colon - a colon is legal in neither a channel name nor a
  # password, whereas a comma is legal in a password.
  @AC-202
  Scenario: A channel can carry its password
    Given no daemon settings and nothing in the connect cache
    When the daemon is started with --channels=team,ops:hunter2
    Then it joins exactly "team, ops"
    And it joins "ops" with the password "hunter2"

  @AC-202
  Scenario: A channel from the settings file is joined by a flag-less start
    Given the settings file records the server "settings.example" on port 1111
    And the settings file records the channel "ops:a,b"
    When the daemon is started with no flags at all
    Then it joins exactly "ops"
    And it joins "ops" with the password "a,b"

  # Forgetting to list the channel you are focusing has an obvious fix, so
  # it is fixed rather than reported.
  @AC-202
  Scenario: A focused channel is joined even when it was left off the list
    Given no daemon settings and nothing in the connect cache
    When the daemon is started with --channels=team --initial-focus=channel:ops
    Then it joins exactly "team, ops"
    And the focus is the channel "ops"

  # Presence is only ever announced within a shared channel, and no message
  # asks "is this person online?" - so a nickname focus with nothing joined
  # would wait for someone it could never be told about.
  @AC-202
  Scenario: Focusing a person with no channels given picks a discovery channel
    Given no daemon settings and nothing in the connect cache
    When the daemon is started with --initial-focus=alice
    Then it joins exactly "the-hall"
    And the focus is a private conversation with alice

  @AC-202
  Scenario: Naming a channel means the-hall is not needed
    Given no daemon settings and nothing in the connect cache
    When the daemon is started with --channels=team --initial-focus=alice
    Then it joins exactly "team"
    And it does not join the-hall
