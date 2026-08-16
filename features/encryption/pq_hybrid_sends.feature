@US-027
Feature: One sealed layout for every kind of pq_hybrid content

  As a user of the quantum-resistant identity
  I want everything I receive to name me as its intended recipient
  So that nothing I am shown was ever meant for somebody else

  A pq_hybrid send - a text message, a file offer, a voice stream, or a
  file's bytes - is always sealed the same way: one setup naming who the
  content is for and which room it belongs to, signed by the sender, plus
  the content itself under a key only that setup unlocks. Text is simply a
  send with one chunk. See docs/PROTOCOL.md.

  @AC-111
  Scenario: A sealed message reaches the person it was sealed for
    Given alice and bob each have a pq_hybrid identity
    When alice seals "meet me at six" for bob
    Then bob reads back exactly what was sealed

  @AC-112
  Scenario: A message sealed for someone else is refused
    Given alice and bob each have a pq_hybrid identity
    And carol also has a pq_hybrid identity
    When alice seals "meet me at six" for bob
    And carol is handed that very same sealed message
    Then carol refuses it

  @AC-113
  Scenario: A private message replayed into a channel is refused
    Given alice and bob each have a pq_hybrid identity
    When alice seals "meet me at six" for bob privately
    And that sealed message is presented as if it belonged to the channel "the-hall"
    Then bob refuses it

  @AC-114
  Scenario: A message that already arrived once is refused the second time
    Given alice and bob each have a pq_hybrid identity
    When alice seals "meet me at six" for bob
    And bob accepts it
    And the very same sealed message arrives again
    Then bob refuses it

  @AC-115 @TB-160
  Scenario: Streamed content is sealed exactly like a text message
    Given alice and bob each have a pq_hybrid identity
    When alice seals a stream of 3 chunks for bob
    Then bob reads back every chunk in that stream
    And the stream's setup is what proved the sender, before any chunk was accepted

  @TB-161
  Scenario: Two chunks of one send never repeat a nonce
    Given alice and bob each have a pq_hybrid identity
    When alice seals a stream of 3 chunks for bob
    Then no two chunks of that stream are byte-identical
