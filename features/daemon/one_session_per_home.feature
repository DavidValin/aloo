@US-038
Feature: One session per aloo home

  As someone running aloo as a daemon and from a terminal
  I want a second session against the same home to be refused
  So that two copies of one pad's counters never write the same keychain

  Every store under a home - the pad counters above all - is written by the
  session that owns it. Two sessions on one home would each seal against
  the same keychain from their own idea of the next position, and desync
  every pad in it for good. A separate session takes a separate home
  (ALOO_HOME).

  See docs/SPEC.md "The daemon".

  @AC-441
  Scenario: A second session against the same home is refused
    Given a session holds the aloo home "shared"
    When another session tries to start against the same home
    Then it is refused, naming the home and ALOO_HOME as the way out

  @AC-441
  Scenario: A session under its own home is unaffected
    Given a session holds the aloo home "shared"
    When another session starts against a different home
    Then it starts

  @AC-441
  Scenario: The home is free again once its session is gone, however it went
    Given a session holds the aloo home "shared"
    When that session ends
    And another session tries to start against the same home
    Then it starts
