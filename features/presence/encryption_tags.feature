@US-012
Feature: Showing how each person's messages are protected

  As a connected user
  I want each person shown with a tag for the scheme protecting them
  So that I can see at a glance when a one-time pad is in play and when it is not

  The tag trails the person's name as an annotation on it - reading "who
  this is, then how they are protected" rather than leading with a
  classification label. There are two: pq_hybrid's shield
  (ML-DSA-87+RSA4096 / ML-KEM-1024+RSA4096 / AES-256-GCM - see
  docs/PROTOCOL.md section 13), and the key that replaces it while a
  one-time pad session is open with that person.
  See docs/SPEC.md "Encryption tag convention".

  @AC-051 @TB-099 @TB-100
  Scenario: The sidebar tags each person with the scheme protecting them
    Given I am connected and viewing a channel
    And dan is in the channel with me using pq_hybrid
    And frank is in the channel with me using pq_hybrid
    Then dan's tag is shown after their name
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
    And dan is in the channel with me using pq_hybrid
    And frank is in the channel with me using pq_hybrid
    Then every tag in the user list ends on the sidebar's right edge
    And every nickname still starts on its left
