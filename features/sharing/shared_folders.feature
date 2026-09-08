@US-066
Feature: Sharing folders with the people I name

  As a user with folders worth handing around
  I want to mark folders as shared and let the people I name browse and
  download from them without me confirming each file
  So that sharing a set of files is a standing arrangement rather than a
  file-by-file conversation

  A share is named in ~/.aloo/settings (or the Ctrl+S File Sharing tab)
  and announced to the peers allowed to see it. They browse it from
  /info and pull what they like; only what they asked for arrives
  without an Accept popup. See docs/PROTOCOL.md 7.8 and docs/SPEC.md
  Functionality #35.

  @AC-448
  Scenario: Sharing a folder from the settings popup
    Given I am connected and viewing a channel
    And I press Ctrl+S
    And I move to the File Sharing tab
    When I share my folder "Photos" with "alice,bob"
    Then the saved shares are "Photos"
    And the saved share line ends with "Photos,alice,bob"

  @AC-448
  Scenario: Two folders with the same name cannot both be shared
    Given I am connected and viewing a channel
    And I press Ctrl+S
    And I move to the File Sharing tab
    And I share my folder "one/Photos" with "all"
    When I share my folder "two/Photos" with "all"
    Then the share form refuses it as already shared
    And the saved shares are "Photos"

  @AC-449
  Scenario: The File Sharing tab holds the upload budget and the folder list
    Given I am connected and viewing a channel
    And I press Ctrl+S
    And I move to the File Sharing tab
    Then the focused setting is "file_sharing_link_speed_kbps"
    When I press Down
    Then the focused setting is "file_sharing_max_pct"
    When I press Down
    Then the focused setting is "shared folders"

  @AC-454
  Scenario: Opening a DM with someone who shares with you says so
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos" with me
    When I open a private room with bob
    Then the room with bob says "bob has given you access to files, type /info to access"

  @AC-454
  Scenario: The notice is not repeated on every visit
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos" with me
    And I have opened a private room with bob
    When I leave and reopen the room with bob
    Then the room with bob says once "bob has given you access to files, type /info to access"

  @AC-457
  Scenario: /info offers to browse the files someone shared
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos" with me
    And I have opened a private room with bob
    When I type "/info"
    And I press Enter
    Then the user info popup offers to browse shared files
    When I press Enter
    Then the shared files browser is open on bob's shares

  @AC-457
  Scenario: Someone who shares nothing has no button to press
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And I have opened a private room with bob
    When I type "/info"
    And I press Enter
    Then the user info popup does not offer to browse shared files

  @AC-451
  Scenario: Entering a shared folder asks its owner what is in it
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos" with me
    And I have opened the shared files browser for bob
    When I press Enter
    Then a listing of "Photos" is requested from bob
    And the browser says it is loading

  @AC-451
  Scenario: A listing shows name, created, updated and size
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos" with me
    And I have opened the shared files browser for bob
    And I press Enter
    When bob answers with the folder "trip" and the file "beach.jpg" of 2500 bytes
    Then the browser row for "beach.jpg" shows its size as "2.5 KB"
    And the browser row for "beach.jpg" shows a created and an updated time
    And the browser names the columns name, created, updated and size

  @AC-453
  Scenario: Pressing d on a file asks bob for that file
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos" with me
    And I have opened the shared files browser for bob
    And I press Enter
    And bob answers with the folder "trip" and the file "beach.jpg" of 2500 bytes
    When I press Down
    And I press the d key
    Then downloading "beach.jpg" from bob's "Photos" is requested

  @AC-452
  Scenario: Pressing d on a folder asks bob for everything under it
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos" with me
    And I have opened the shared files browser for bob
    And I press Enter
    And bob answers with the folder "trip" and the file "beach.jpg" of 2500 bytes
    When I press the d key
    Then downloading "trip" from bob's "Photos" is requested

  @AC-455
  Scenario: A file you asked for arrives without a popup
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob offers me "beach.jpg" as a file I asked for
    Then no file offer popup is shown
    And that offer is handed to the session to accept

  @AC-455
  Scenario: A file nobody asked for still gets its popup
    Given I am connected and viewing a channel
    And bob is in the channel with me
    When bob offers me the file "surprise.bin" of 2048 bytes in the channel
    Then a file offer popup from bob for "surprise.bin" of 2048 bytes is shown

  @AC-450
  Scenario: A withdrawn folder disappears from the browser
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos,Public" with me
    And I have opened the shared files browser for bob
    When bob shares "Public" with me instead
    Then the browser lists only "Public"

  @AC-460
  Scenario: A folder download keeps its layout
    Given bob shares a folder holding "trip/beach.jpg"
    When I download "trip" from it
    Then the file lands under "fileshare/bob/Photos/trip/beach.jpg"

  @AC-461
  Scenario: A folder inside a shared folder stays private
    Given bob shares a folder with me holding a folder only alice may see
    Then browsing it does not list the folder only alice may see
    And asking for that folder by name is refused
    And downloading the whole share leaves it out

  @AC-463
  Scenario: The Downloads tab lists what is arriving
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos" with me
    And I have opened the shared files browser for bob
    And a download of "Photos/holiday" from bob is half done
    Then the browser title says "Downloading 1..."
    When I press Tab
    Then the downloads tab shows "Photos/holiday" with a progress bar

  @AC-464
  Scenario: Cancelling a download keeps what already arrived
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos" with me
    And I have opened the shared files browser for bob
    And a download of "Photos/holiday" from bob is half done
    And I press Tab
    When I press the c key
    Then cancelling that download is requested

  @AC-464
  Scenario: A finished download can be cleared, a running one cannot
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos" with me
    And I have opened the shared files browser for bob
    And a download of "Photos/holiday" from bob is half done
    And a download of "Photos" from bob has finished
    And I press Tab
    When I press the x key
    Then the downloads tab still lists 2 downloads
    When I press Down
    And I press the x key
    Then the downloads tab still lists 1 downloads

  @AC-462
  Scenario: A download does not appear in the conversation
    Given I am connected and viewing a channel
    And bob is in the channel with me
    And bob has shared "Photos" with me
    And I have opened the shared files browser for bob
    And a download of "Photos/holiday" from bob is half done
    Then the room with bob holds no file row

  @AC-468
  Scenario: The transfers popup opens on its own shortcut
    Given I am connected and viewing a channel
    When I press the transfers shortcut
    Then the transfers popup is open
    When I press the transfers shortcut
    Then the transfers popup is closed

  @AC-466 @AC-467
  Scenario: The transfers popup lists both directions
    Given I am connected and viewing a channel
    And a download of "Photos/holiday" from alice is running
    And an upload of "Photos" to bob has finished
    When I press the transfers shortcut
    Then the transfers popup lists "Photos/holiday" from alice
    And the transfers popup lists "Photos" to bob
    And the transfers popup says 1 transfer is running

  @AC-469
  Scenario: Either side can stop a transfer from the popup
    Given I am connected and viewing a channel
    And a download of "Photos/holiday" from alice is running
    And I press the transfers shortcut
    When I press the c key
    Then cancelling that download is requested

  @AC-469
  Scenario: An upload someone is pulling can be stopped too
    Given I am connected and viewing a channel
    And an upload of "Photos" to bob is running
    And I press the transfers shortcut
    When I press the c key
    Then cancelling that upload is requested
