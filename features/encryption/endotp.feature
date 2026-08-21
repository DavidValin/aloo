@US-033
Feature: Ending a one-time-pad session with /endotp

  As a user with an active one-time-pad session
  I want to be able to end it myself, or have it survive a disconnect until
  either of us ends it
  So that I control when the extra pad layer stops, and a peer merely going
  offline never quietly ends it for me

  See docs/PROTOCOL.md section 16.6. The full send/receive/acknowledge wiring
  (pausing the local pad - kept, not destroyed, so a later /otp with the same
  contact resumes it - notifying the peer, retrying that notice on reconnect)
  needs a live session and is verified manually with two clients
  (docs/TESTING.md "Known coverage gaps") - these scenarios cover what is
  observable at the compose bar and in local session state.

  @AC-192
  Scenario: /endotp in an open private room ends the session
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I type "/endotp" into the compose bar
    And I press Enter
    Then the otp session was ended
    And the compose bar is empty

  @AC-192
  Scenario: /endotp outside any private room does nothing
    Given I am connected and viewing a channel
    When I type "/endotp" into the compose bar
    And I press Enter
    Then nothing happens

  @AC-053
  Scenario: /endotp still works once the peer has gone offline
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And bob has gone offline
    When I type "/endotp" into the compose bar
    Then the compose bar holds "/endotp"
    When I press Enter
    Then the otp session was ended

  @AC-193
  Scenario: A disconnect alone does not end an active session
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And the otp session with bob is active
    When bob goes offline
    Then the otp session with bob is still active
