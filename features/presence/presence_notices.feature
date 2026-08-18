@US-034
Feature: Presence notices in the message log

  As a user watching a channel or a private conversation
  I want a plain, timestamped notice when someone joins, leaves, or
  disconnects
  So that I know who is still around without guessing from silence

  Layered on top of channel membership (docs/SPEC.md "Channels") and
  offline handling (Functionality #7): the notice itself is a
  `MessageBody::Presence` log line, rendered in yellow with a local-time
  prefix, distinct from the gray/italic `MessageBody::System` app
  narration OTP already uses.

  @AC-149
  Scenario: A live join is announced, timestamped and yellow
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When carol joins the channel with me
    Then the channel log ends with the presence notice "carol joined"

  @AC-149 @TB-190
  Scenario: The initial membership snapshot is not announced as a join
    Given I am connected and viewing a channel
    And bob is in the channel with me
    Then no presence notice appears in the channel log

  @AC-150
  Scenario: Someone leaving the channel is announced
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob leaves the channel
    Then the channel log ends with the presence notice "bob left"

  @AC-151
  Scenario: A disconnect is announced in every shared channel and an open DM
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When bob goes offline
    Then the channel log ends with the presence notice "bob disconnected"
    And bob's private room ends with the presence notice "bob disconnected"
