@US-037
Feature: Muting a person's voice messages

  As a user with one contact who talks a lot
  I want their voice messages to stop playing themselves the moment they land
  So that I am not interrupted, while still being able to hear them when I choose

  Muting is deliberately not a block. The message still arrives, still
  decrypts and still appears in the log - only the live playback is
  suppressed, so Enter replays it whenever you want. It is keyed on the
  nickname rather than the connection, which is what lets it persist in
  ~/.aloo/settings and apply to someone who is not even online yet.

  See docs/SPEC.md Functionality #15.

  @AC-195
  Scenario: Muting and unmuting a person's voice messages
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/mute-voice bob"
    And I press Enter
    Then bob's voice messages are muted
    And the compose bar is empty
    When I type "/unmute-voice bob"
    And I press Enter
    Then bob's voice messages are not muted

  @AC-195
  Scenario: Either command with no nickname lists who is muted
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob's voice messages are muted
    When I type "/mute-voice"
    And I press Enter
    Then nothing happens
    And a status notice names bob

  @AC-195
  Scenario: With nobody muted, the bare command says so
    Given I am connected and viewing a channel
    When I type "/mute-voice"
    And I press Enter
    Then a status notice says "no voices muted"

  @AC-195
  Scenario: Muting someone already muted changes nothing
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob's voice messages are muted
    When I type "/mute-voice bob"
    And I press Enter
    Then nothing happens
    And a status notice says "already muted"

  # A nickname never contains whitespace, so a second word is a typo -
  # muting the first word of it silently would be worse than refusing.
  @AC-195
  Scenario: A nickname with a space in it is refused rather than guessed at
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/mute-voice bob carol"
    And I press Enter
    Then nothing happens
    And bob's voice messages are not muted
    And a status notice says "one nickname"

  # These are the first commands in this app that take an argument, so the
  # thing most likely to break is the unknown-command catch-all eating them.
  @AC-195
  Scenario: A near-miss still reaches the unknown-command notice
    Given I am connected and viewing a channel
    When I type "/mute-voic bob"
    And I press Enter
    Then a status notice says "unknown command"

  @AC-196
  Scenario: A muted message still arrives and can still be replayed
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob's voice messages are muted
    And bob starts streaming a voice message into the channel
    When bob's voice message finishes after 2000 milliseconds
    Then playback from bob is suppressed
    And it becomes a replayable voice message of 2000 milliseconds, in place

  @AC-196
  Scenario: An unmuted sender is heard as usual
    Given I am connected and viewing a channel
    And bob is in the channel with me
    Then playback from bob is not suppressed

  @AC-198
  Scenario: Someone can be muted before they ever connect
    Given I am connected and viewing a channel
    When I type "/mute-voice eve"
    And I press Enter
    Then eve's voice messages are muted
    When eve joins the channel with me
    Then playback from eve is suppressed
