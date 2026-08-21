@US-038
Feature: Starting aloo in the background

  As someone who wants the walkie-talkie shortcut always available
  I want aloo to connect in the background and stay connected
  So that I can talk from any app without opening aloo first

  A daemon is told what to be by flags first, then by the daemon_ keys in
  ~/.aloo/settings, then by the last connection made from the connect
  screen, then by built-in defaults - the same precedence `aloo --server`
  already uses for its own flags. That is what lets a service unit run a
  bare `aloo --daemon` and get back the configuration set up by hand once.

  See docs/SPEC.md "Running in background mode".

  @AC-201
  Scenario: A flag wins over everything remembered
    Given the settings file records the server "settings.example" on port 1111
    When the daemon is started with --host=flag.example
    Then it connects to "flag.example" on port 1111

  @AC-201
  Scenario: The settings file fills in what the flags left out
    Given the settings file records the server "settings.example" on port 1111
    And the settings file records the nickname "david"
    When the daemon is started with no flags at all
    Then it connects to "settings.example" on port 1111
    And it connects as "david"

  # The last thing you connected to by hand is a better guess than a
  # built-in default, and it is what makes a bare `aloo --daemon` work on a
  # machine that has only ever used the connect screen.
  @AC-201
  Scenario: The last hand-made connection is the fallback
    Given the connect cache remembers "cache.example" on port 3333
    When the daemon is started with no flags at all
    Then it connects to "cache.example" on port 3333

  @AC-201
  Scenario: With no server named anywhere it refuses rather than guessing
    Given no daemon settings and nothing in the connect cache
    When the daemon is started with no flags at all
    Then it refuses to start, saying "no server to connect to"

  @AC-201
  Scenario: The two server credentials cannot both be given
    Given no daemon settings and nothing in the connect cache
    When the daemon is started with both --server-pwd and --server-key
    Then it refuses to start, saying "mutually exclusive"

  @AC-201
  Scenario: A misspelled channel is reported rather than quietly dropped
    Given no daemon settings and nothing in the connect cache
    When the daemon is started with --channels=not-a-name-because-it-is-far-too-long
    Then it refuses to start, saying "not a usable channel name"

  # A first `aloo --daemon` on a machine that has only ever been used
  # interactively needs no flags at all - not even --nick.
  @AC-241
  Scenario: A first daemon reuses the last connection made by hand
    Given the connect screen last connected as "dave" to "chat.example.com" port 6667
    When the daemon is started with no flags at all
    Then it connects to "chat.example.com" on port 6667
    And it connects as "dave"

  @AC-241
  Scenario: A previous daemon start still comes first
    Given the connect screen last connected as "dave" to "chat.example.com" port 6667
    And the settings file records the server "settings.example" on port 1111
    And the settings file records the nickname "david"
    When the daemon is started with no flags at all
    Then it connects to "settings.example" on port 1111
    And it connects as "david"
