@US-007
Feature: Streaming a voice message to the channel

  As a connected user
  I want my voice to stream to the channel as I speak
  So that the other side hears me without waiting for me to finish

  Voice is never one whole message: it is a Start, then chunks as they are
  captured, then an End carrying the real duration - all sharing one
  stream_id, delivered over a peer-to-peer link punched between the two
  clients (Start/End reliably, chunks unreliably). See docs/PROTOCOL.md
  section 7.3 and "Direct peer-to-peer transport".

  @AC-039 @TB-037 @AC-100
  Scenario: Voice arrives as an ordered start, chunk and end
    Given a server that anyone may connect to
    And alice has connected
    And bob has connected
    And alice and bob are both in the channel "general"
    When alice streams a voice message to "general" addressed to bob
    Then bob receives the voice message start, chunk and end in that order
