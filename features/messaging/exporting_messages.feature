@US-054
Feature: Exporting specific channels and DMs on demand

  As a user who wants a snapshot of particular conversations right now
  I want a popup, reachable at any time, to pick exactly which joined
  channels and open DMs to dump to disk
  So that I don't have to turn on continuous autosave (US-053) just to save
  a copy of what's already on screen

  Ctrl+E opens the popup; Cancel is focused by default, the same
  destructive-action-default convention every other Confirm/Cancel popup in
  this app uses. Confirming writes each checked surface's current log to
  ~/.aloo/exports/<server>/{channels,dms}/, files prefixed with one fresh
  short id shared by the whole export.

  @AC-358
  Scenario: Ctrl+E opens the export popup with everything unchecked
    Given I am connected and viewing a channel
    When I press Ctrl+E
    Then the export popup is open with channel general unchecked

  @AC-358
  Scenario: Checking a channel and confirming exports it
    Given I am connected and viewing a channel
    When I press Ctrl+E
    And I press Enter
    And I press Tab
    And I press Left
    And I press Enter
    Then exporting channel general is requested
    And the export popup is closed

  @AC-358
  Scenario: Cancel closes the popup without exporting anything
    Given I am connected and viewing a channel
    When I press Ctrl+E
    And I press Enter
    And I press Tab
    And I press Enter
    Then nothing happens
    And the export popup is closed

  @AC-358
  Scenario: Escape always backs out with no export
    Given I am connected and viewing a channel
    When I press Ctrl+E
    And I press Escape
    Then nothing happens
    And the export popup is closed
