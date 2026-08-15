@US-024
Feature: A direct link only forms with someone you actually share a channel with

  As a connected user
  I want my client to ignore a direct-link request from someone I don't
  currently share a joined channel with
  So that a stranger who merely learns my UserId can't get my client to
  respond to them at all

  The server's own relay performs no relationship checking of its own
  (docs/PROTOCOL.md section 7.0) - this is the one place that boundary is
  actually enforced. See docs/PROTOCOL.md section 7.0.2.

  These scenarios exercise the decision predicate directly
  (`UiState::shares_a_joined_channel`) rather than the live socket path that
  consults it (`session::handle_server_message`'s `PeerCandidates` arm),
  which needs a real connection and has no cucumber harness today - see
  docs/TESTING.md's known coverage gaps.

  @TB-155
  Scenario: A channel-mate's request is recognized as one to accept
    Given I am connected and viewing a channel
    And bob is in the channel with me
    Then I would accept a direct link request from bob

  @TB-155
  Scenario: A stranger's request is recognized as one to ignore
    Given I am connected and viewing a channel
    Then I would not accept a direct link request from a stranger
