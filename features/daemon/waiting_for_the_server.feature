@US-038
Feature: Waiting for the server

  As someone whose daemon starts at login, before the network does
  I want it to keep trying to reach the server rather than give up
  So that the shortcut works the moment the network is up, without me restarting anything

  A daemon's commonest first failure is not a wrong host: it is being
  started before the wifi is, or on a laptop whose wifi is off. Exiting
  there turns "the network was not up yet" into "the daemon is gone" until
  someone notices. So an unreachable server is waited for, on the same
  schedule a live session already reconnects on - and the daemon stays
  reachable throughout: --daemon-status says where the wait is up to, a
  terminal that attaches is shown it, and --daemon-stop ends it. Only an
  answer from the server - a wrong password, a taken nickname - is still
  the startup failure it always was.

  See docs/SPEC.md "Running in background mode", "Waiting for the server".

  @AC-442
  Scenario: A server that is not there yet is waited for, not given up on
    Given nothing is listening where the daemon expects its server
    When the daemon starts against it
    Then it is still trying a moment later, with its status saying "waiting for the server"
    When the server comes up there
    Then the daemon connects to it
    And its status goes back to saying it is running

  @AC-442
  Scenario: Stopping a daemon that is still waiting ends it cleanly
    Given nothing is listening where the daemon expects its server
    When the daemon starts against it
    And it is asked to stop while still waiting
    Then it exits cleanly, never having connected

  @AC-442
  Scenario: A terminal attaching during the wait is told what is going on
    Given nothing is listening where the daemon expects its server
    When the daemon starts against it
    And a terminal attaches while it is still waiting
    Then that terminal is shown "cannot reach" and "trying again in"

  @AC-442
  Scenario: A wrong password is an answer, not an outage
    Given a server that knows alice
    When the daemon starts against it with the wrong password
    Then it refuses to start, saying "authentication failed"
    And it never waited
