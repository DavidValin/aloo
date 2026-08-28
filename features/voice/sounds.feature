@US-062
Feature: Silencing any part of aloo that makes noise

  As a user in an open-plan office, or on a call
  I want to turn off arriving voice, the end-of-message tone, and the event sounds independently
  So that I can keep using aloo where a sound would be unwelcome

  Three switches, all on out of the box, each silencing exactly one thing.
  end.wav belongs to roger_beep and to nothing else, which is why turning
  the event sounds off leaves it alone. See docs/SPEC.md Functionality #32; the Ctrl+S popup that flips them is
  features/settings/settings_popup.feature.

  @AC-402
  Scenario: All three sounds are on until someone says otherwise
    Given a settings file that says
      """
      global_ptt_enabled=true
      """
    Then arriving voice plays itself
    And the end-of-message tone plays
    And the event sounds play

  @AC-402
  Scenario: Each switch silences only its own sound
    Given a settings file that says
      """
      sound_notifications=off
      """
    Then the event sounds are silent
    And the end-of-message tone plays
    And arriving voice plays itself

  @AC-402
  Scenario: Turning autoplay off silences everyone, not just the muted
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When arriving voice is turned off
    Then bob's arriving voice is kept off the speakers
    And carol's arriving voice is kept off the speakers

  @AC-415
  Scenario: Nobody's voice playing is said once, in the header
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob's voice is muted
    Then bob is marked as muted in the sidebar
    And the header says nothing about playback
    When arriving voice is turned off
    Then the header says playback is off
    And bob is not singled out in the sidebar
