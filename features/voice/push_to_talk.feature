@US-007
Feature: Sending a voice message by holding a key

  As a connected user
  I want to hold Space and have my voice stream to whatever I am looking at
  So that speaking is as immediate as typing

  The recording goes wherever the eye is: the selected channel, or an open
  private room. Audio is streamed as it is captured rather than recorded and
  sent as one lump. See docs/SPEC.md Functionality #4.

  @AC-032
  Scenario: Holding Space streams to the channel I am viewing
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And focus is on the log
    When I hold Space
    Then a voice message starts streaming to the channel, addressed to bob
    And a recording indicator is shown
    When I release Space
    Then the voice message is sent

  @AC-032
  Scenario: Holding Space in a private room streams to that person instead
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And focus is on the log
    When I hold Space
    Then a voice message starts streaming privately to bob
    When I release Space
    Then the voice message is sent

  @AC-033
  Scenario: Space in the compose bar is just a space
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "hello all"
    Then the compose bar holds "hello all"

  @AC-034
  Scenario: Holding Space with nowhere to send does not record
    Given I am connected but have not joined any channel
    And focus is on the log
    When I hold Space
    Then no recording starts

  @AC-035
  Scenario: An incoming voice message appears while it is still arriving
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob starts streaming a voice message into the channel
    Then the channel log shows a streaming placeholder from bob
    When bob's voice message finishes after 4200 milliseconds
    Then it becomes a replayable voice message of 4200 milliseconds, in place

  @AC-035
  Scenario: My own voice message appears immediately too
    Given I am connected and viewing a channel
    When my own voice message starts streaming into the channel
    Then my own streaming placeholder appears immediately
    When my own voice message finishes after 900 milliseconds
    Then it becomes a replayable voice message of 900 milliseconds, in place

  @AC-035
  Scenario: A private voice message finalises in place as well
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob starts streaming a voice message into our private room
    When bob's private voice message finishes after 1000 milliseconds
    Then the private room shows a replayable voice message of 1000 milliseconds

  @AC-036
  Scenario: Enter on a finished voice message replays it
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has left me a finished voice message
    And focus is on the log
    When I press Enter
    Then replaying that voice message is requested

  @AC-036
  Scenario: Enter on a text message replays nothing
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has left me a text message
    And focus is on the log
    When I press Enter
    Then nothing happens

  @AC-037 @TB-049
  Scenario Outline: A voice message is labelled with its own real length
    Then a voice message of <ms> milliseconds is labelled "<label>"

    Examples:
      | ms    | label          |
      | 0     | voice (0sec)   |
      | 1     | voice (1sec)   |
      | 999   | voice (1sec)   |
      | 1001  | voice (2sec)   |
      | 3000  | voice (3sec)   |
      | 12000 | voice (12sec)  |
      | 47000 | voice (47sec)  |

  @AC-038 @TB-043
  Scenario: A recorder that will not start stops pretending it did
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And focus is on the log
    When I hold Space
    Then a recording indicator is shown
    When the recorder fails with "no input device available"
    Then the UI stops claiming to record
    And the audio failure "no input device available" is never shown on screen

  @AC-038 @TB-044
  Scenario: A playback failure does not disturb a recording in progress
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And focus is on the log
    When I hold Space
    And playback fails with "no output device available"
    Then the recording carries on regardless
    And the audio failure "no output device available" is never shown on screen
