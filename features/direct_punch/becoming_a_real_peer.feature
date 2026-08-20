@US-039
Feature: A punched peer becomes someone I can actually see and talk to

  As someone running aloo in the background with direct punching on
  I want a peer reached with no server to appear and behave like any other
  So that my channels, my focus and my push-to-talk work the same either way

  A punch on its own only opens a path. What turns that path into a person
  is an envelope that opens under the key already pinned for their
  nickname: that proves who they are, and it carries the channels they are
  in, so both sides can place each other in the channels they share. Until
  that arrives nobody is registered - the nickname on a punch datagram is
  unauthenticated and names nobody. See docs/PROTOCOL.md 7.1.5.

  @AC-215
  Scenario: An unauthenticated punch does not make anyone a peer
    Given alice has no pinned identity for "mallory"
    Then "mallory" cannot become an addressable peer

  @AC-215
  Scenario: A pinned identity that cannot sign is refused
    Given alice has a pinned identity for "bob" that is not a pq_hybrid one
    Then "bob" cannot become an addressable peer

  @AC-214
  Scenario: A punched peer joins the channels we both are in
    Given alice has joined "general" and "dev"
    When bob announces over the direct link that he is in "general" and "elsewhere"
    Then bob is placed in "general"
    And bob is not placed in "elsewhere"

  @AC-214
  Scenario: The announcement is authoritative, so leaving is announced by omission
    Given alice has joined "general" and "dev"
    And bob is already placed in "general"
    When bob announces over the direct link that he is in "dev"
    Then bob is placed in "dev"
    And bob is removed from "general"

  @AC-214
  Scenario: A peer who leaves every shared channel is still someone I can DM
    Given alice has joined "general" and "dev"
    And bob is already placed in "general"
    When bob announces over the direct link that he is in no channels
    Then bob is removed from "general"
    And bob is still an addressable peer

  @TB-224
  Scenario: Leaving a channel does not tear down a link the schedule owns
    Given alice and bob each list the other for direct punching every minute
    And their scheduled link is up
    Then leaving a channel does not forget the link to bob

  @TB-214
  Scenario: Listing someone who has not listed you reaches nobody
    Given bob lists peter for direct punching
    And peter lists somebody else instead
    When both of them punch on the shared grid
    Then bob has no link to peter
    And peter has no link to bob
    And peter has no record of bob at all
