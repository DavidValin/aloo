@US-041
Feature: Knowing whether the message you sent got there

  As someone who has just sent a message
  I want to see whether it reached the people it was addressed to
  So that I know whether silence means nobody answered or nobody got it

  Delivery is a claim only the recipient can make: the sender names its
  message, and the recipient answers for that name once it has actually
  decrypted the content. The transport's own ack says a datagram arrived,
  which is a weaker claim, and is deliberately not used for this. See
  docs/PROTOCOL.md 7.1.1 and 7.2.1.

  @AC-230
  Scenario: A private message starts undelivered and turns delivered
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I type "did you get this"
    And I press Enter
    Then my last message in the room with bob is undelivered
    When bob acknowledges my last message
    Then my last message in the room with bob is delivered

  @AC-230
  Scenario: Only the messages I sent carry an indicator
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "hello"
    And I have opened a private room with bob
    Then bob's message in the room with bob carries no delivery indicator
    And bob's message reads "bob: hello"

  @AC-230
  Scenario: The arrow says how far my message has got
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I type "did you get this"
    And I press Enter
    Then my message reads "me -> did you get this"
    And its arrow is grey
    When bob acknowledges my last message
    Then its arrow is green

  @AC-231
  Scenario: A message that did reach somebody is not struck through
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And focus is on the compose
    When I type "morning"
    And I press Enter
    Then my last message in "general" is not struck through

  @AC-231
  Scenario: A channel message is delivered to some before it is delivered to all
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And focus is on the compose
    When I type "morning both"
    And I press Enter
    Then my last message in "general" is undelivered
    When bob acknowledges my last message
    Then my last message in "general" is partly delivered
    And its arrow is orange
    When carol acknowledges my last message
    Then my last message in "general" is delivered
    And its arrow is green

  @AC-231
  Scenario: A channel message addressed to nobody is never delivered, and says so
    Given I am connected and viewing a channel
    And focus is on the compose
    When I type "anyone there"
    And I press Enter
    Then my last message in "general" is undelivered
    And my last message in "general" is struck through

  @AC-232
  Scenario: The details of a message name every user it went to, and how far it got
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And focus is on the compose
    When I type "status check"
    And I press Enter
    And bob acknowledges my last message
    And I move focus to the log
    And I press the i key
    Then the message details name "bob" as DELIVERED
    And the message details name "carol" as UNDELIVERED
    And the message details show when it was sent

  @AC-232
  Scenario: The details popup owns the screen until it is closed
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And focus is on the compose
    When I type "one"
    And I press Enter
    And I move focus to the log
    And I press the i key
    And I press Up
    Then the message details are still open
    When I press Escape
    Then the message details are closed

  @AC-232
  Scenario: A message that arrived here has no delivery information to show
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has sent me the private message "hello"
    And I have opened a private room with bob
    And focus is on the log
    When I press the i key
    Then the message details say there is no delivery information

  @AC-230
  Scenario: A voice message and a file transfer carry the arrow too
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I record a voice message to the channel
    And I offer bob a file
    Then both of those rows carry a delivery arrow
    And both are undelivered

  @AC-235
  Scenario: A file is answered twice - once for the offer, once for the file
    Given bob has been offered a file that names one of my messages
    Then nothing further is owed merely because the offer arrived
    When the whole file arrives and is decrypted on his side
    Then my message is acknowledged

  @AC-235
  Scenario: A transfer that fails part way earns no second answer
    Given bob has been offered a file that names one of my messages
    When his side fails part way through
    Then nothing is acknowledged

  @AC-233
  Scenario: A message is acknowledged only once it could actually be read
    Given a session that can read messages sent to it
    When a peer sends me a message they sealed to my key
    Then that message is acknowledged as decrypted
    When a peer sends me a message sealed to somebody else's key
    Then nothing more is acknowledged

  @AC-236
  Scenario: A voice message the recipient has heard reads differently from one they have not
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I record a voice message to the channel
    And bob reports he decrypted it
    Then the message details name "bob" as DELIVERED
    When bob reports he played it
    Then the message details name "bob" as DELIVERED+LISTENED

  @AC-236
  Scenario: A file the recipient has on disk reads differently from one they only saw offered
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I offer bob a file
    And bob reports he decrypted it
    Then the message details name "bob" as DELIVERED
    When bob reports he saved it
    Then the message details name "bob" as DELIVERED+SAVED

  @AC-328
  Scenario: A file the recipient previewed without saving reads as VIEWED
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I offer bob a file
    And bob reports he decrypted it
    Then the message details name "bob" as DELIVERED
    When bob reports he viewed it
    Then the message details name "bob" as DELIVERED+VIEWED

  @AC-328
  Scenario: A saved file never regresses to VIEWED, even if a late view report arrives
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I offer bob a file
    And bob reports he decrypted it
    And bob reports he saved it
    And bob reports he viewed it
    Then the message details name "bob" as DELIVERED+SAVED

  @AC-236
  Scenario: A text message never grows an extra state, and the arrow never shows one
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And focus is on the compose
    When I type "hello"
    And I press Enter
    And bob reports he played it
    Then my last message in "general" is delivered
    And the message details name "bob" as DELIVERED
    And the message details show no extra state

  @AC-233
  Scenario: A message sent over a direct link is acknowledged back to the sender
    Given alice and bob each list the other for direct punching every minute
    And their scheduled link is up
    Then a message alice sends over that link is acknowledged back to her

  @AC-233 @TB-230
  Scenario: A message that names nothing asks for no acknowledgement
    Given alice and bob each list the other for direct punching every minute
    And their scheduled link is up
    Then a message alice sends without naming it is never acknowledged

  @AC-242
  Scenario: The details popup says how the message was encrypted
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    And focus is on the compose
    When I type "hello"
    And I press Enter
    And I open the details of my last message
    Then the details name the encryption scheme by its mechanism
    And the details name the key it was sealed to

  @AC-242
  Scenario: A line this client wrote itself reports no encryption
    Given I am connected and viewing a channel
    When carol joins the channel with me
    And I open the details of my last message
    Then the details report no encryption at all
