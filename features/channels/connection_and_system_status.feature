@US-018
Feature: System and connection health indicators

  As a connected user
  I want my own CPU load and a rough read on how lively the connection is,
  shown right in the channel view
  So that I can tell whether something feels slow because of my machine or
  the network

  @AC-071
  Scenario: CPU usage sits right before the help hint, colored by threshold
    Given I am connected and viewing a channel
    When CPU usage is sampled at 24 percent
    Then the header shows "CPU:24%" right before "Ctrl+H: Help"
    And the header shows "CPU:24%" in green
    When CPU usage is sampled at 25 percent
    Then the header shows "CPU:25%" in red

  @AC-072
  Scenario: Conn quality defaults to a white dash before any traffic
    Given I am connected and viewing a channel
    Then the header shows "Conn:-" in white

  @AC-072
  Scenario: Conn quality sits right before the CPU indicator, colored by quality
    Given I am connected and viewing a channel
    When the connection quality is classified as Good
    Then the header shows "Conn:GOOD" right before "CPU:"
    And the header shows "Conn:GOOD" in green
    When the connection quality is classified as Normal
    Then the header shows "Conn:NORMAL" in yellow
    When the connection quality is classified as Bad
    Then the header shows "Conn:BAD" in red
