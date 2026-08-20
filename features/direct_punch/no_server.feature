@US-039
Feature: Running with no server at all

  As someone who only wants to reach a few people I already know
  I want to run aloo with no server whatsoever
  So that nothing has to be set up, trusted, or kept running for us to talk

  A server is only ever needed to introduce people and to track channel
  membership. With --no-server neither happens: the peers come from
  direct_punch_to, the channels from direct_punch_channel, and everything
  that actually carries content was already peer-to-peer. What genuinely
  needs a server is refused when asked for, by name - never silently
  dropped. See docs/PROTOCOL.md 7.1.5 and docs/SPEC.md.

  @AC-218
  Scenario: No server and an unreachable server are explained differently
    Then running with no server explains a refusal as permanent
    And an unreachable server explains the same refusal as temporary

  @AC-219
  Scenario: Only genuinely server-backed things are refused
    Then "joining a channel" needs a server
    And "OTP mail" needs a server
    And sending a message does not need a server
    And ending a call does not need a server
    And leaving a channel does not need a server

  @AC-217
  Scenario: The configured channels are the only ones that exist
    Given a settings file that says
      """
      direct_punch=on
      direct_punch_channel=general
      direct_punch_channel=dev
      direct_punch_channel=general
      """
    Then the channels available without a server are "general" and "dev"
