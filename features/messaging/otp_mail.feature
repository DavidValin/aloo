@US-035
Feature: OTP mail that waits, encrypted, on the server

  As a user with an established one-time pad for a contact
  I want to write them a mail - subject, text, voice recordings and file
  attachments - that waits encrypted on the server while they are offline
  So that we can communicate with one-time-pad secrecy without both having
  to be online at the same moment

  The server stores only an opaque pad-sealed blob it holds no key
  material for, and deletes it the moment the recipient acknowledges
  decrypting it. See docs/PROTOCOL.md section 17.

  @AC-154
  Scenario: The /mail command opens a full-screen mail compose view
    Given I am connected and viewing a channel
    And bob is in the channel with me
    Then the mail compose view is not open
    When I type "/mail"
    And I press Enter
    Then the mail compose view is open
    And the mail's To, Subtext and Content fields are all empty

  @AC-154
  Scenario: Escape discards the compose view
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/mail"
    And I press Enter
    And I type "bob"
    And I press Escape
    Then the mail compose view is not open

  @AC-155
  Scenario: An unpinned recipient renders invalid with a cross
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/mail"
    And I press Enter
    And I type "stranger"
    Then a recipient check was requested for "stranger"
    When the recipient check answers that "stranger" is not pinned
    Then the To field renders invalid, red, with a cross

  @AC-155
  Scenario: A pinned recipient with enough key renders valid with a tick
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/mail"
    And I press Enter
    And I type "bob"
    And the recipient check answers that "bob" has a 5 MB key
    Then the To field renders valid, green, with a tick

  @AC-156
  Scenario: The remaining key in MB tracks the mail as it grows
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/mail"
    And I press Enter
    And I type "bob"
    And the recipient check answers that "bob" has a 5 MB key
    Then the remaining key is displayed in the top right, in MB
    When I note the remaining key
    And I move to the mail content field
    And I type "hello bob"
    Then the remaining key shrank by 9 bytes
    When I note the remaining key
    And a 1000 byte voice recording finishes for the mail
    Then the remaining key shrank by 1000 bytes

  @AC-157
  Scenario: An attachment longer than the remaining key is cancelled
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/mail"
    And I press Enter
    And I type "bob"
    And the recipient check answers that "bob" has a key with 100 spare bytes
    And a 200 byte voice recording finishes for the mail
    Then the recording was cancelled, not attached
    When a 50 byte voice recording finishes for the mail
    Then the mail has 1 attachment

  @AC-158
  Scenario: Removing an attachment needs confirmation
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/mail"
    And I press Enter
    And a 50 byte voice recording finishes for the mail
    And I move to the mail attachments pane
    And I press the d key
    Then a removal confirmation is open
    When I press Enter
    Then the mail has 1 attachment
    When I press the d key
    And I press Left
    And I press Enter
    Then the mail has 0 attachments

  @AC-159
  Scenario: Sending needs explicit confirmation
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/mail"
    And I press Enter
    And I type "bob"
    And the recipient check answers that "bob" has a 5 MB key
    And I press Ctrl+S
    Then a send confirmation is open
    When I press Enter
    Then no send was produced and the compose view is still open
    When I press Ctrl+S
    And I press Tab
    And I press Enter
    Then the send action was produced

  @AC-159 @TB-193
  Scenario: A retry re-uploads the recovered ciphertext, never a fresh encode
    Given alice and bob have provisioned an otp contact for each other
    When alice seals an otp mail for bob
    Then the keychain's last-sent copy replays the very same ciphertext
    And bob decrypts it back to the sealed bytes

  @AC-160
  Scenario: A mail for an offline recipient waits on the server disk
    Given a server with otp mail storage
    And alice has connected
    When alice uploads an otp mail addressed to bob
    Then the server acknowledges the mail as stored
    And the mail's ciphertext waits on the server's disk

  @AC-160
  Scenario: The recipient fetches, acknowledges, and the server copy is deleted
    Given a server with otp mail storage
    And alice has connected
    When alice uploads an otp mail addressed to bob
    Then the server acknowledges the mail as stored
    When bob has connected
    And bob fetches his otp mail
    Then bob is handed the stored mail intact
    When bob acknowledges the mail
    Then the mail's ciphertext is gone from the server's disk

  @AC-161
  Scenario: The sender learns of delivery on their next connect
    Given a server with otp mail storage
    And alice has connected
    When alice uploads an otp mail addressed to bob
    Then the server acknowledges the mail as stored
    When alice disconnects
    And bob has connected
    And bob fetches his otp mail
    And bob acknowledges the mail
    Then the mail's ciphertext is gone from the server's disk
    When alice reconnects and fetches her otp mail
    Then alice is told the mail was delivered
    When alice confirms the delivery receipt
    Then the server forgets the delivery receipt

  @AC-162
  Scenario: The mailbox shows delivery status, and a received mail can be read
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When I type "/mailbox"
    And I press Enter
    Then the mailbox was requested
    When the mailbox holds a delivered mail to bob and a received mail from alice
    Then the mailbox lists the mail to bob as delivered, without its content
    When I select the received mail and press Enter
    Then a read of the received mail was requested

  @AC-163
  Scenario: A received mail rests as ciphertext plus pad and dies with them
    Given a fresh client mail store
    When a decrypted mail payload is stored re-padded
    Then the store holds a ciphertext file and a pad file for it
    And neither file alone contains the payload
    And reading the mail decrypts it in memory
    When the mail is removed
    Then both files are destroyed and the mail is unreadable

  @TB-194
  Scenario: A mail sealed for a different identity never touches the pad
    Given my pad contact for the claimed sender is "aaa-bbb" expecting sequence 3
    When a mail sealed under contact "aaa-ccc" arrives at sequence 3
    Then the mail is refused before the pad is touched
    When a mail sealed under contact "aaa-bbb" arrives at sequence 3
    Then the mail is admitted to the one genuine decrypt
    When a mail sealed under contact "aaa-bbb" arrives at sequence 1
    Then the mail is only re-acknowledged
    When a mail sealed under contact "aaa-bbb" arrives at sequence 7
    Then the mail waits for the earlier spend

  @TB-195
  Scenario: A tampered mail fails its identity signature
    Given alice and bob each have a pq_hybrid identity
    When alice signs a mail payload
    Then the signature verifies against alice's pinned identity
    And a single flipped payload bit no longer verifies
    And bob's identity does not verify it either

  @TB-196
  Scenario: Mail ids are validated before any path is built from them
    Given a server mail store in a scenario directory
    Then freshly generated mail ids are 32 lowercase hex characters
    And a mail with a path-shaped id is refused by the store
