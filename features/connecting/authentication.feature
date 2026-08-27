@US-002
Feature: Logging in with a nickname and its password

  As a server operator
  I want every client to log in with a registered nickname and its password
  So that only people who hold an account I recognise can join

  There is one way in: a nickname and its password, checked against the
  server's users registry. See docs/PROTOCOL.md section 5.

  @AC-013
  Scenario: The right nickname and password get in
    Given a server with alice registered under the password "s3cret"
    When alice logs in with the password "s3cret"
    Then the connection is accepted

  @AC-013 @AC-014
  Scenario: The wrong password does not
    Given a server with alice registered under the password "s3cret"
    When alice logs in with the password "wrong"
    Then the connection is refused

  @AC-014
  Scenario: A nickname nobody registered is refused the same way as a wrong password
    Given a server that anyone may connect to
    When alice logs in with the password "whatever"
    Then the connection is refused

  @AC-386
  Scenario: Seven wrong passwords in a row ban that address's logins
    Given a server with alice registered under the password "s3cret"
    When alice fails 7 login attempts in a row
    And alice logs in with the password "s3cret"
    Then the connection is refused, naming "too many failed login attempts"
