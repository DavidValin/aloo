@US-025
Feature: Protecting a private channel with a password

  As a user creating or rejoining a private channel
  I want to set a password when I create it, and be asked for it again to
  rejoin
  So that someone who merely learns or guesses its name can't join it

  A private channel is still never advertised (US-004's Ctrl+J-by-name model
  is unchanged) - a password is an extra gate on top of that, not a
  replacement for it. See docs/PROTOCOL.md section 6.5/6.6.

  @AC-104
  Scenario: Creating a private channel with a password lets someone who knows it join
    Given a running server registry
    And alice and bob are registered users
    When alice creates the private channel "vault" with the password "s3cret!"
    And bob joins the private channel "vault" with the password "s3cret!"
    Then bob is confirmed as joined to "vault"

  @AC-105
  Scenario: Joining without a password opens the password popup
    Given I am connected but have not joined any channel
    When I press Ctrl+J
    And I type "vault"
    And I press Enter
    And the server reports that "vault" requires a password
    Then the channel password popup is open for "vault"
    And no password error is shown

  @AC-105
  Scenario: A wrong password is retried from the same popup
    Given I am connected but have not joined any channel
    When I press Ctrl+J
    And I type "vault"
    And I press Enter
    And the server reports that the password for "vault" was wrong
    Then the channel password popup is open for "vault"
    And the password error "wrong password" is shown
    When I type "s3cret!"
    And I press Enter
    Then joining the private channel "vault" with password "s3cret!" is requested

  @AC-106
  Scenario: Too many wrong attempts bans further tries against that channel
    Given a running server registry
    And alice is a registered user who created the private channel "vault" with the password "s3cret!"
    And bob is a registered user who never joins anything
    When bob attempts to join "vault" with the wrong password 8 times from the same address
    Then the eighth attempt is reported as banned, not merely wrong
