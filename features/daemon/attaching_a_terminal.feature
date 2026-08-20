@US-038
Feature: Borrowing the session from a terminal

  As someone with a daemon already connected
  I want to read the log and type from any terminal
  So that I can use the session I already have instead of starting another

  Typing `aloo` with a daemon running attaches to it rather than opening
  the connect screen: the same connection, the same peer links, the same
  open conversations. `/daemon` hands it back.

  Nothing is re-connected in that hand-off, and nothing a viewer does can
  end the session. Quitting a terminal is not the same as stopping the
  daemon - `aloo --daemon-stop` is, deliberately a different command.

  See docs/SPEC.md "Running in background mode".

  @AC-203
  Scenario: A terminal attaches and drives the session
    Given a daemon is running with nobody attached
    When a terminal attaches to it
    Then the session starts drawing at the terminal's size
    When the attached terminal types x
    Then the session receives that keystroke

  @AC-203
  Scenario: Detaching gives the session back without ending it
    Given a daemon is running with nobody attached
    And a terminal has attached to it
    When the attached terminal detaches
    Then the session stops drawing
    And the session is still running

  # A closed window or a crashed viewer never says goodbye. The session
  # must still stop drawing into a socket that is gone - and must survive.
  @AC-203
  Scenario: A terminal vanishing without warning does not take the session
    Given a daemon is running with nobody attached
    And a terminal has attached to it
    When the attached terminal is closed without warning
    Then the session stops drawing
    And the session is still running

  @AC-203
  Scenario: Asking for status does not disturb the session
    Given a daemon is running with nobody attached
    When the daemon is asked for its status
    Then the answer says it is running
    And the session is told nothing

  @AC-203
  Scenario: Only a deliberate shutdown ends the session
    Given a daemon is running with nobody attached
    When the daemon is asked to shut down
    Then the session is told to end
