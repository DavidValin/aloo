@US-038
Feature: Keeping a one-time-pad session up in the background

  As someone who talks to one person under a one-time pad
  I want the daemon to make sure that session is running
  So that my voice is pad-encrypted the moment I hold the shortcut

  --otp asks for a session to *exist*, which is two different jobs. A
  session outlives both sides disconnecting and even restarting the app -
  only /endotp ends one (docs/PROTOCOL.md 16.6) - and aloo resumes it
  automatically when the peer reappears. Inviting on top of that would put
  an Accept/Reject popup in front of someone already in the session, and
  spend a fresh pad handshake to arrive back where they started.

  See docs/SPEC.md "Running in background mode".

  @AC-199
  Scenario: A person with no session is invited
    Given a daemon focused on alice with --otp
    When alice appears
    Then an OTP session is proposed
    And the focus moves to them

  @AC-199
  Scenario: A session that is already running is continued, not re-proposed
    Given a daemon focused on alice with --otp
    And an OTP session is already active with alice
    When alice appears
    Then no OTP session is proposed
    And the focus moves to them

  # A peer on a flapping connection must not become a queue of popups.
  @AC-199
  Scenario: Only one invitation is sent however often they reconnect
    Given a daemon focused on alice with --otp
    When alice appears
    Then an OTP session is proposed
    When alice appears
    Then no OTP session is proposed

  @AC-199
  Scenario: Without --otp nobody is ever invited
    Given a daemon focused on alice
    When alice appears
    Then no OTP session is proposed

  @AC-199
  Scenario: Someone other than the focused person is never invited
    Given a daemon focused on alice with --otp
    When bob appears
    Then no OTP session is proposed

  # OTP is provisioned pairwise, per contact - there is no channel-wide form.
  @AC-199
  Scenario: Asking for OTP on a channel focus is refused
    Given no daemon settings and nothing in the connect cache
    When the daemon is started with --initial-focus=channel:ops --otp
    Then it refuses to start, saying "needs a person"
