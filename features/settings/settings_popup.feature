@US-061
Feature: Changing settings without leaving the app

  As a user who wants a different shortcut, a quieter client, or a peer to punch at
  I want to edit ~/.aloo/settings from inside aloo, grouped and explained
  So that I do not have to quit, find a file, and start again to change my mind

  Control+S opens the same file the app reads at startup, in three tabs.
  Every change is written the moment it is made - there is no Save button,
  so nothing can be typed and then lost on Escape. See docs/SPEC.md
  "Settings".

  @AC-397
  Scenario: Control+S opens the settings, on the General tab
    Given I am connected and viewing a channel
    When I press Ctrl+S
    Then the settings popup is open on the "General" tab
    And the settings popup asked the session to load the file
    And the focused setting is "global_ptt_enabled"

  @AC-397
  Scenario: Tab walks the three tabs and comes back round
    Given I am connected and viewing a channel
    And I press Ctrl+S
    When I press Tab
    Then the settings popup is open on the "Direct Punch" tab
    When I press Tab
    Then the settings popup is open on the "OTP" tab
    When I press Tab
    Then the settings popup is open on the "General" tab

  @AC-397
  Scenario: Each tab starts on its own first field
    Given I am connected and viewing a channel
    And I press Ctrl+S
    When I move the focus to "resume_from_log"
    And I press Tab
    Then the focused setting is "direct_punch"

  @AC-397
  Scenario: Up and Down walk one tab's fields, wrapping
    Given I am connected and viewing a channel
    And I press Ctrl+S
    When I press Down
    Then the focused setting is "global_ptt_shortcut"
    When I press Up
    And I press Up
    Then the focused setting is "queue_send_messages"

  @AC-397
  Scenario: Escape closes the settings
    Given I am connected and viewing a channel
    And I press Ctrl+S
    When I press Escape
    Then the settings popup is closed

  @AC-404
  Scenario: Space flips the switch instead of starting a recording
    Given I am connected and viewing a channel
    And I press Ctrl+S
    When I press Space
    Then the setting "global_ptt_enabled" is off
    And no voice recording was started

  @AC-405
  Scenario: The open tab is filled, and the areas are spaced apart
    Given I am connected and viewing a channel
    And I press Ctrl+S
    Then the "General" tab is drawn as the open one
    And a blank row separates each bordered area

  @AC-406
  Scenario: Queueing sends is the last switch on the General tab
    Given I am connected and viewing a channel
    And I press Ctrl+S
    When I move the focus to "queue_send_messages"
    Then the setting "queue_send_messages" is on
    When I press Space
    Then the setting "queue_send_messages" is off
    And the settings popup asked the session to save

  @AC-398
  Scenario: A switch flips with Space and is saved on the spot
    Given I am connected and viewing a channel
    And I press Ctrl+S
    When I move the focus to "roger_beep"
    Then the setting "roger_beep" is on
    When I press Space
    Then the setting "roger_beep" is off
    And the settings popup asked the session to save

  @AC-398
  Scenario: Every switch on the General tab is its own
    Given I am connected and viewing a channel
    And I press Ctrl+S
    When I move the focus to "sound_notifications"
    And I press Space
    Then the setting "sound_notifications" is off
    And the setting "roger_beep" is on
    And the setting "voice_autoplay" is on

  @AC-399
  Scenario: Typing into a box fills it, and the equals sign is refused
    Given I am connected and viewing a channel
    And I press Ctrl+S
    When I press Tab
    And I move the focus to "noip_hostname"
    And I type "home=me.ddns.net" into the focused setting
    Then the setting "noip_hostname" reads "homeme.ddns.net"

  @AC-399
  Scenario: The punch list is one stop that the arrows walk into and out of
    Given I am connected and viewing a channel
    And I press Ctrl+S
    And two direct punch targets are configured
    When I press Tab
    And I move the focus to "configured punches"
    Then the selected punch row is 0
    When I press Down
    Then the selected punch row is 1
    When I press Down
    Then the focused setting is "noip_when_no_server_and_direct_punch_is_active"

  @AC-400
  Scenario: The percentage box takes digits only
    Given I am connected and viewing a channel
    And I press Ctrl+S
    When I press Tab
    And I press Tab
    And I move the focus to "otp_low_key_warn_pct"
    And I clear the focused setting
    And I type "2x5" into the focused setting
    Then the setting "otp_low_key_warn_pct" reads "25"

  @AC-401
  Scenario: Every field on a tab explains itself in a line
    Given I am connected and viewing a channel
    And I press Ctrl+S
    Then every field on the open tab is explained beneath it
    When I press Tab
    Then every field on the open tab is explained beneath it
    When I press Tab
    Then every field on the open tab is explained beneath it
