@US-030
Feature: Keeping the setup conversation off the wire too

  As a user on a network I do not control
  I want the conversation that sets my session up to be encrypted as well
  So that someone watching the wire learns neither my password nor who I talk to

  Message content has never touched the server. But the control channel
  that gets a session going always travelled as plain TCP, and it carries
  plenty worth having: a login's nickname and password, which channels
  exist, who is in them, and when. Encrypting it changes nothing about
  what the server itself learns - it still has to route by these - only
  what anyone in between does. See docs/PROTOCOL.md.

  This layer's own offer is ephemeral and unauthenticated on its own -
  vouching for the server is TLS's job (server_ssl, see
  features/connecting - "Encrypting the connection to the server with
  TLS" once that server is running one), a separate, optional layer this
  file does not test.

  @AC-126
  Scenario: The setup conversation is encrypted before anything is said
    Given a server offering an encrypted control channel
    When a client accepts the offer
    Then both sides hold the same keys
    And each direction has a key of its own

  @AC-127
  Scenario: A password does not appear on the wire
    Given a server offering an encrypted control channel
    When a client accepts the offer
    And the client sends the password "hunter2" through the channel
    Then the password cannot be found anywhere in the bytes sent

  @TB-169
  Scenario: The same message twice does not look the same twice
    Given a server offering an encrypted control channel
    When a client accepts the offer
    And the client sends the same message twice
    Then the two sealed frames differ
