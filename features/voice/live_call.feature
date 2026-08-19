@US-036
Feature: Live voice calls

  As a connected user
  I want to start a continuous, multi-user voice call in a channel or private room
  So that a group of people can talk together in real time without anyone holding a key down

  Distinct from a push-to-talk voice message ("Sending a voice message by
  holding a key"): /call rings every reachable member/the peer with an
  Accept/Reject popup, accepting joins a shared, unbounded call instead of
  sending one clip, and a permanent red indicator marks the whole time it's
  active. See docs/SPEC.md and docs/PROTOCOL.md, both "Live voice calls".

  @AC-167
  Scenario: An incoming call invite names the caller, Accept focused by default
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob is calling me in the channel
    Then a call invite popup names bob
    When I press Enter
    Then accepting bob's call is requested

  @AC-168
  Scenario: Rejecting a call invite clears it and shows the next one queued
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And bob is calling me in the channel
    And carol is calling me in the channel
    When I press Left
    And I press Enter
    Then rejecting bob's call is requested
    When that decision is applied
    Then a call invite popup names carol

  @AC-169
  Scenario: A permanent call indicator tracks participants and mute state
    Given I am connected and viewing a channel
    Then no call indicator is shown
    When I join a call in the channel
    Then a call indicator is shown
    And the call indicator shows 0 connected
    When bob joins the call with me
    Then the call indicator shows 1 connected
    When I mute myself
    Then the call indicator shows muted
    When I leave the call
    Then no call indicator is shown

  @AC-170
  Scenario: /mute only works while on a call
    Given I am connected and viewing a channel
    When I type "/mute"
    And I press Enter
    Then a call status notice says "not on a call"
    When I join a call in the channel
    And I type "/mute"
    And I press Enter
    Then muting is requested

  @AC-171
  Scenario: /call refuses a second call, and /endcall only works on one
    Given I am connected and viewing a channel
    When I type "/endcall"
    And I press Enter
    Then a call status notice says "not on a call"
    When I join a call in the channel
    And I type "/call"
    And I press Enter
    Then a call status notice says "already on a call"
    When I type "/endcall"
    And I press Enter
    Then ending the call is requested
