@US-042
Feature: Reading a warning without it wrecking the screen

  As a user running aloo in a terminal
  I want the app's own warnings to go somewhere I can read them rather than
  into the middle of the interface
  So that the screen stays legible and the warning still reaches me

  A task running in the background decides it has something to say at any
  moment - a STUN reply that cannot be used, an audio device that went away,
  a store that would not save. Written straight out, those bytes land wherever the cursor
  happens to be and tear a hole through whatever frame was on screen. Every
  one of them goes through one sink instead, which is silenced for exactly
  as long as ratatui holds the terminal. See docs/SPEC.md "Where diagnostics
  go".

  # One scenario rather than two: the sink is a single process-wide switch,
  # and `cargo bdd` runs scenarios concurrently, so a second scenario
  # flipping it would be describing the first one's state as much as its
  # own.
  @AC-244
  Scenario: A warning waits for the terminal, then is written out
    Given the interface has taken the terminal over
    When a background task warns "direct-link UDP receive error"
    Then nothing is written to the terminal
    When the interface hands the terminal back
    Then the warning is written out, prefixed as the app's own
    When a background task warns "could not read ~/.aloo/settings"
    Then that warning is not held back
