@US-012
Feature: Showing how each person's identity is protected

  As a connected user
  I want each person shown with a tag for how durable their identity is
  So that I can tell a file-backed identity from one regenerated every session

  Every tag trails the person's name as an annotation on it, one shared
  convention across all three my_key types - reading "who this is, then how
  durable their identity is" rather than leading with a classification
  label. Every tag still means real per-recipient encryption (RSA, or for
  pq_hybrid, ML-DSA-87+RSA4096/ML-KEM-1024+RSA4096/AES-256-GCM - see
  docs/PROTOCOL.md section 13) - the icon is about identity durability, not
  secrecy.
  See docs/SPEC.md "Encryption tag convention".

  @AC-051 @TB-099 @TB-100
  Scenario: The sidebar tags each person according to how they hold their key
    Given I am connected and viewing a channel
    And dan is in the channel with me using password
    And eve is in the channel with me using none
    And frank is in the channel with me using pq_hybrid
    Then dan's tag is shown after their name
    And eve's tag is shown after their name
    And frank's tag is shown after their name

  @AC-051 @TB-035
  Scenario: A private room titles itself with the peer's tag too
    Given I am connected and viewing a channel
    And bob is in the channel with me using pq_hybrid
    When I open a private room with bob
    Then the private room title reads "Private: bob" with the pq_hybrid tag after the name

  @AC-245
  Scenario: The tags line up down the right edge of the user list
    Given I am connected and viewing a channel
    And dan is in the channel with me using password
    And frank is in the channel with me using pq_hybrid
    Then every tag in the user list ends on the sidebar's right edge
    And every nickname still starts on its left
