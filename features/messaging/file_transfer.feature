@US-019
Feature: Sending a file to a channel or a user

  As a connected user
  I want to send a local file to the current channel or an open DM, and save
  one I receive
  So that I can share something beyond plain text without leaving the
  terminal

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
  Scenario: Confirming Send file sends it to every other channel member
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And carol is in the channel with me
    And I have selected the file "report.pdf" containing "hello file transfer" to send to the channel
    When I press Left
    And I press Enter
    Then sending "report.pdf" as a file to the channel is requested, addressed to bob and carol
    And my message is shown in the channel log as mine

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
  Scenario: An oversized file is rejected instead of sent
    Given I am connected and viewing a channel
    And I have selected an oversized file to send to the channel
    When I press Left
    And I press Enter
    Then the file is rejected as too large

  @AC-076
  Scenario: A received file renders as a paperclip and its filename
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob sends me the file "photo.png" in the channel
    Then the message log shows a file "photo.png" from bob

  @AC-078
  Scenario: A file from a peer with an unresolved identity review is held until accepted
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob's identity mismatches
    And bob sends me the file "secret.docx" in the channel
    Then bob's file "secret.docx" is held, not shown
    When I accept the review
    Then the message log shows a file "secret.docx" from bob
