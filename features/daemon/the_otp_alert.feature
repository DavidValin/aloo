@US-038
Feature: Hearing when a background OTP session fails to start

  As someone running a daemon focused on one person with --otp
  I want to hear about it when that session does not start
  So that I do not talk to them believing my voice is pad-protected

  This is the one failure a --otp daemon cannot recover from on its own.
  The peer is online, the focus is on them, the shortcut is ready - and
  what it would send is no longer wrapped in the one-time pad that was
  asked for. Nobody is looking at the screen, so it makes a noise.

  Success is silent: the daemon doing exactly what it was told is not news.
  And a session somebody typed /otp for themselves is silent either way -
  they are sitting there watching the outcome.

  See docs/SPEC.md, "Running in background mode".

  @AC-205
  Scenario: A session the daemon asked for failing is audible
    Given the daemon has proposed an OTP session
    When the OTP session fails because "they declined"
    Then the alert sound plays

  @AC-205
  Scenario: A session that starts says nothing
    Given the daemon has proposed an OTP session
    When the OTP session starts
    Then no alert sound plays

  # The refusals that never reach the peer at all - no otp binary, either
  # side not pq_hybrid, an unreadable identity - are just as final, and
  # no acknowledgement will ever arrive to resolve them.
  @AC-205
  Scenario: A proposal refused before it is even sent is audible too
    Given the daemon has proposed an OTP session
    When the OTP session fails because "the otp command is not installed"
    Then the alert sound plays

  @AC-205
  Scenario: A session somebody typed /otp for is not announced
    Given alice typed /otp themselves
    When the OTP session fails because "they declined"
    Then no alert sound plays

  @AC-205
  Scenario: The outcome is reported once, not once per message about it
    Given the daemon has proposed an OTP session
    When the OTP session fails because "they declined"
    Then the alert sound plays
    And a second outcome changes nothing
