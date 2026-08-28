@US-039
Feature: Punching a direct link with no server involved

  As a user who already knows where a particular person's machine is
  I want my client to reach them on a schedule we both keep
  So that we can talk with no server arranging it, or none running at all

  Everything a server would normally supply - who the peer is, where they
  are, and when both of us will probe at once - comes instead from
  ~/.aloo/settings and from the wall clock. Both ends run the same
  frequency, both grids restart at every o'clock, so both probe at the same
  moments with nothing coordinating them. See docs/PROTOCOL.md 7.1.5 and
  docs/SPEC.md "Direct punch settings".

  @AC-212
  Scenario: Turning it on and naming who to punch at
    Given a settings file that says
      """
      direct_punch=on
      direct_punch_to=bob,bobpublic.com,every_1min
      direct_punch_to=marco,marcohost.com,every_1h
      """
    Then direct punching is on
    And bob is punched at "bobpublic.com" every 1 minutes
    And marco is punched at "marcohost.com" every 60 minutes
    And a peer named with no port of its own uses the well-known direct punch port

  @AC-320 @direct_otp @without_reachable_server
  Scenario: A peer may be named by device, addressing one specific machine
    Then "bob+laptop,203.0.113.9,every_5m" names nickname "bob" device "laptop"
    And "bob+phone,203.0.113.9,every_5m" names nickname "bob" device "phone"
    And "bob,203.0.113.9,every_5m" names nickname "bob" with no device

  # Reference table no-server row 6: alice's two devices each hold their
  # own independently-generated raw key for bob, but only one is
  # reachable until a second, device-suffixed line names the other -
  # a configuration gap, not a refusal (docs/PROTOCOL.md 7.1.5's
  # continuation, device-pinning plan §5a).
  @AC-321 @direct_otp @without_reachable_server
  Scenario: A second device stays unreachable until a device-suffixed line is added
    Given bob lists alice's device "laptop" for direct punching
    Then bob can reach alice's device "laptop"
    And bob has no line at all for alice's device "phone"
    When bob also lists alice's device "phone" for direct punching
    Then bob can reach alice's device "phone"
    And bob can still reach alice's device "laptop"

  @AC-212
  Scenario: A peer may be named by address or by name, with a port of its own
    Then "bob,203.0.113.9,every_5m" names host "203.0.113.9" on the well-known port
    And "bob,203.0.113.9:9000,every_5m" names host "203.0.113.9" on port 9000
    And "bob,2001:db8::1,every_5m" names host "2001:db8::1" on the well-known port
    And "bob,[2001:db8::1]:9000,every_5m" names host "2001:db8::1" on port 9000
    And "bob,bobpublic.com:9000,every_5m" names host "bobpublic.com" on port 9000

  @AC-213
  Scenario: A line with a typo says so instead of quietly doing nothing
    Given a settings file that says
      """
      direct_punch=on
      direct_punch_to=bob,bobpublic.com,every_1m
      direct_punch_to=carol,carolhost.com,every_3m
      direct_punch_to=dave,not a host,every_1h
      """
    Then bob is punched at "bobpublic.com" every 1 minutes
    And 2 direct punch lines are reported as unusable, each with a reason

  @AC-206 @AC-207
  Scenario: Two peers meet on the clock and open a link that carries a message
    Given alice and bob each list the other for direct punching every minute
    When the next slot on their shared grid comes round
    Then alice and bob have a direct link to each other
    And no candidate exchange was ever relayed through a server
    And a message alice sends over that link arrives at bob

  @AC-208
  Scenario: A slot arriving on a link that is already up changes nothing
    Given alice and bob each list the other for direct punching every minute
    And their scheduled link is up
    When four more slots come and go
    Then alice's link to bob is still up on the same address

  @AC-209
  Scenario: An attempt gives up after the punch window and waits for its slot
    Given alice lists bob for direct punching every minute, at an address nobody answers
    When the next slot on their shared grid comes round
    Then alice is punching at bob
    When the punch window elapses
    Then alice is no longer punching at bob
    And no reconnect budget has been spent
    When the next slot on their shared grid comes round
    Then alice is punching at bob

  @AC-210
  Scenario: A direct-only link that drops is re-punched, but not forever
    Given alice and bob each list the other for direct punching every minute
    And their scheduled link is up
    When bob disappears and the link goes quiet
    Then alice re-punches at bob straight away, outside the schedule
    And she gives up after 5 reconnect attempts and waits for her next slot

  @AC-211
  Scenario: A peer being punched directly is never also asked for through a server
    Given alice lists bob for direct punching every minute, at an address nobody answers
    When the next slot on their shared grid comes round
    And alice tries to send bob a message
    Then nothing is sent to the server about bob
    And no retry ever asks the server to relay candidates for bob

  @AC-211
  Scenario: The same person reached both ways still has one link
    Given alice lists bob for direct punching every hour
    Then alice files bob under a peer id no server could have handed out
    When the server tells alice that bob is user 7
    Then alice files bob under user 7
    When bob goes offline on the server
    Then alice files bob under a peer id no server could have handed out

  @AC-290
  Scenario: The status line reports how many direct punches are active
    Given I am connected and viewing a channel
    And direct punching has 1 of 2 peers active, next try in 37 seconds
    Then the header shows "1/2 (next: 37s)" right before "Conn:"
