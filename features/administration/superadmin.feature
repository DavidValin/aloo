@US-052
Feature: Server superadmins

  As a server operator
  I want a short list of trusted accounts able to lock an account out (or
  back in) over the wire
  So that abuse can be handled without needing shell access to the
  server's own machine

  `/activate` and `/deactivate` deliberately share their vocabulary with
  the pre-existing email activation code: one concept ("make this account
  able to log in right now"), reached two ways. See docs/PROTOCOL.md
  section 5.5.

  @AC-344
  Scenario: A superadmin's deactivation blocks the next login, citing the reason
    Given a server with alice as its only superadmin
    And alice has connected
    And eve is registered on the server
    When alice deactivates eve with the reason "spamming"
    And eve attempts to log in with her password
    Then the login is refused, citing "spamming"

  @AC-345
  Scenario: A currently-connected target is told live, not just on their next login
    Given a server with alice as its only superadmin
    And alice has connected
    And eve has connected
    When alice deactivates eve with the reason "spamming"
    Then eve is told their account has been deactivated, citing "spamming"

  @AC-344
  Scenario: Activating reverses a deactivation
    Given a server with alice as its only superadmin
    And alice has connected
    And eve is registered on the server
    When alice deactivates eve with the reason "spamming"
    And alice activates eve
    And eve attempts to log in with her password
    Then the login succeeds

  @AC-344
  Scenario: Activating also clears a still-pending email registration
    Given a server with alice as its only superadmin
    And alice has connected
    And eve has registered but not yet activated her account
    When alice activates eve
    And eve attempts to log in with her password
    Then the login succeeds

  @AC-344 @AC-348 @TB-262
  Scenario: A non-superadmin's attempt is refused and changes nothing
    Given a server with alice as its only superadmin
    And alice has connected
    And mallory has connected
    And eve is registered on the server
    When mallory deactivates eve with the reason "not really an admin"
    Then mallory is told the command is not allowed
    When eve attempts to log in with her password
    Then the login succeeds
