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
  Scenario: m on my own row mutes my microphone
    Given I am connected and viewing a channel
    When I open a call in the channel
    And I press the m key
    Then muting is requested

  @AC-188
  Scenario: Accepting an invite to a call that has already ended joins nothing
    Given I am connected and viewing a channel
    And bob is calling me in the channel
    When that call ends before I answer
    And I press Enter
    Then no call invite is accepted
    And a call status notice says "that call has already ended"
    And no call invite popup is open

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

  @AC-175 @AC-176
  Scenario: The call modal lists the host first and labels everyone on it
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    When bob hosts a call I am on
    And carol is invited to the call
    Then the call modal is shown
    And the call modal names bob as the host
    And the call modal lists carol as INVITED
    When carol declines the call
    Then the call modal lists carol as REJECTED
    When the host mutes bob
    Then the call modal lists bob as MUTED

  @AC-176
  Scenario: The call modal counts the call's duration live
    Given I am connected and viewing a channel
    When I open a call in the channel
    Then the call modal shows the duration "00:00"
    When the call has been running for 65 seconds
    Then the call modal shows the duration "01:05"

  @AC-177
  Scenario: Escape folds the call modal into the top row, and Ctrl+R reopens it
    Given I am connected and viewing a channel
    When I open a call in the channel
    Then the call modal is shown
    When I press Escape
    Then the call modal is not shown
    And the call indicator is shown in the top row
    When I press Ctrl+R
    Then the call modal is shown

  @AC-178
  Scenario: END CALL in the modal asks before it leaves the call
    Given I am connected and viewing a channel
    When I open a call in the channel
    And I press Enter
    Then the end-call confirmation is open
    And the call is still running
    When I press Enter
    Then the end-call confirmation is closed
    And the call is still running

  @AC-178
  Scenario: Confirming the question is what leaves the call
    Given I am connected and viewing a channel
    When I open a call in the channel
    And I press Enter
    And I move onto END CALL and confirm
    Then ending the call is requested

  @AC-179
  Scenario: Only the host can mute someone from the roster
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I open a call in the channel
    And bob joins the call with me
    And I press Down
    And I press the m key
    Then muting bob is requested

  @AC-179
  Scenario: A participant who is not the host cannot mute anyone
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob hosts a call I am on
    And I press Down
    And I press the m key
    Then nothing is requested

  @AC-180
  Scenario: The host invites one more person from the modal
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I open a call in the channel
    And I press the i key
    And I press Enter
    Then inviting bob to the call is requested

  @AC-181
  Scenario: /call says how many users it will invite before inviting any
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    When I type "/call"
    And I press Enter
    Then the call confirmation says "2 users"
    And no call is started
    When I press Enter
    Then starting the call is requested

  @AC-182
  Scenario: /call with nobody reachable ends before it starts
    Given I am connected and viewing a channel
    When I type "/call"
    And I press Enter
    Then a call status notice says "Call has ended: no one was invited"
    And no call is started

  @AC-183
  Scenario: The host leaving ends the call for everyone
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob hosts a call I am on
    And the host leaves the call
    Then no call indicator is shown
    And a call status notice says "Call has ended: the host left the call"

  @AC-184
  Scenario: A call to a peer under an OTP session is refused before it is confirmed
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And an OTP session is active with bob
    And I have opened a private room with bob
    When I type "/call"
    And I press Enter
    Then a call status notice says "voice calls aren't supported over an OTP session"
    And no call confirmation is shown
    And no call is started
