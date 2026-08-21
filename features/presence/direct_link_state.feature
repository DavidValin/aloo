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

  @AC-228
  Scenario: A closed connection outranks whatever the link was last doing
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "hi"
    And I have a direct connection to bob
    Then bob's name is shown in green
    When bob goes offline
    Then bob's name is shown in gray, whatever his link was last doing

  @AC-229
  Scenario: An open DM is coloured on the top row the same way the sidebar colours it
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And I have a direct connection to bob
    Then the DM selector shows bob in green
    When the direct connection to bob is lost
    Then the DM selector shows bob in red

  @AC-229
  Scenario: Every room the DM dropdown lists carries its peer's reachability
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And I have opened a private room with bob
    And I have opened a private room with carol
    Then every room listed in the DM dropdown carries its peer's reachability

