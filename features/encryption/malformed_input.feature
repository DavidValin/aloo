@US-031
Feature: Surviving input nobody meant to send

  As a user whose client talks to strangers over a network
  I want malformed, truncated or hostile input to fail as an error
  So that nobody can crash my client by sending it nonsense

  Anything arriving from a peer, a server or a file on disk is input a
  stranger may have chosen. None of it may take the client down - and
  "takes it down" includes being talked into reserving more memory than
  exists, which is what an unbounded length prefix invites. See
  docs/SECURITY.md.

  @AC-129
  Scenario: Nonsense from a stranger is refused, not fatal
    When a peer sends 500 messages of pure noise
    Then every one is refused and the client is still running

  @AC-129
  Scenario: A message cut short partway is refused, not fatal
    When a peer sends a message truncated at every possible length
    Then every one is refused and the client is still running

  @TB-172
  Scenario: A frame claiming an impossible size is refused outright
    When a peer announces a frame larger than the protocol allows
    Then the frame is refused without reserving room for it
