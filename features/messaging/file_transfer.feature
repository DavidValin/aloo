@US-019
Feature: Sending a file to a channel or a user

  As a connected user
  I want to send a local file to the current channel or an open DM with the
  recipient's explicit consent, and have an accepted file stream straight to
  disk
  So that I can share something beyond plain text without leaving the
  terminal, and without either side risking an unwanted transfer

  @AC-073
  Scenario: Typing /file opens the browser when a channel is joined
    Given I am connected and viewing a channel
    When I type "/file"
    And I press Enter
    Then the compose bar is empty

  @AC-073
  Scenario: Typing /file does nothing with no channel joined and no DM open
    Given I am connected but have not joined any channel
    When I type "/file"
    And I press Enter
    Then the compose bar holds "/file"

  @AC-074 @AC-075
  Scenario: Confirming Send file offers it to every other channel member
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And I have selected the file "report.pdf" containing "hello file transfer" to send to the channel
    When I press Left
    And I press Enter
    Then sending "report.pdf" as a file to the channel is requested, addressed to bob and carol

  @AC-074
  Scenario: Discard returns to the browser instead of sending
    Given I am connected and viewing a channel
    And I have selected the file "notes.txt" containing "draft" to send to the channel
    When I press Enter
    Then the file selection is discarded, returning to the browser

  @AC-075
  Scenario: Confirming Send file to an open private room addresses that peer
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have selected the file "photo.png" containing "binarydata" to send to bob
    When I press Left
    And I press Enter
    Then sending "photo.png" as a file to bob is requested

  @AC-077
  Scenario: There is no size cap on a file send
    Given I am connected and viewing a channel
    And I have selected a large file to send to the channel
    When I press Left
    And I press Enter
    Then sending "big.bin" as a file to the channel is requested

  @AC-097
  Scenario: A filename over 230 characters is cropped before being offered
    Given I am connected and viewing a channel
    And I have selected a file with a 250-character filename to send to the channel
    When I press Left
    And I press Enter
    Then the offered filename is cropped to 230 characters

  @AC-095
  Scenario: A received file offer shows a popup naming the sender, file and size, Accept focused by default
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob offers me the file "photo.png" of 2048 bytes in the channel
    Then a file offer popup from bob for "photo.png" of 2048 bytes is shown
    When I press Enter
    Then the file offer from bob for "photo.png" is accepted

  @AC-076
  Scenario: Accepting an offer reveals an in-progress row, then completes
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob offers me the file "photo.png" of 2048 bytes in the channel
    When I accept the file offer
    Then the message log shows an in-progress file "photo.png" from bob
    When that transfer reaches 1024 of 2048 bytes
    Then the message log shows "photo.png" at 50 percent
    When that transfer completes
    Then the message log shows a file "photo.png" from bob

  @AC-096
  Scenario: Rejecting an offer shows as rejected in the sender's log
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have selected the file "report.pdf" containing "hello file transfer" to send to the channel
    And I press Left
    And I press Enter
    When bob rejects my file offer
    Then my file "report.pdf" to bob is shown as rejected

  @AC-078
  Scenario: A file offer from a peer with an unresolved identity review is held until accepted
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob's identity mismatches
    And bob offers me the file "secret.docx" of 4096 bytes in the channel
    Then bob's file offer for "secret.docx" is held, not shown
    When I accept the review
    Then a file offer popup from bob for "secret.docx" of 4096 bytes is shown
