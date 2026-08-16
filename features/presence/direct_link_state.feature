@US-024
Feature: Seeing who I can actually reach

  As a user whose messages travel directly to the people I am talking to
  I want to see at a glance whether that direct connection is really up
  So that I am never left typing into a link that quietly goes nowhere

  Being connected to the server and being reachable are not the same thing:
  a peer can be perfectly present in the channel and still have no direct
  path to me, in which case nothing I send them arrives. The sidebar colours
  each name by the state of the direct link, not by presence. See
  docs/PROTOCOL.md 7.1 and docs/SPEC.md "Connected UI".

  @AC-135
  Scenario: A reachable peer is green and an unreachable one is red
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And I have a direct connection to carol
    And the direct connection to bob has been lost
    Then carol's name is shown in green
    And bob's name is shown in red

  @AC-135
  Scenario: A peer whose link is still being punched is shown as neither
    Given I am connected and viewing a channel
    And bob is in the channel with me
    Then bob's name is shown in yellow

  @AC-135
  Scenario: Losing the link to someone still in the channel turns them red
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have a direct connection to bob
    Then bob's name is shown in green
    When the direct connection to bob is lost
    Then bob's name is shown in red
