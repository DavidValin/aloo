@US-001
Feature: Filling in the connect form

  As a user starting the client
  I want to say where the server is, who I am, and how my key material is sourced
  So that I can join a conversation on it

  Nothing here has connected to anything yet: this is the modal the client
  opens with, described in docs/SPEC.md's "Not connected UI".

  @AC-001
  Scenario: The form opens ready to type the host
    Given the connect form is open
    Then the host field has the cursor in it

  @AC-002 @TB-012
  Scenario: Typing fills the focused field and Backspace takes it back
    Given the connect form is open
    When I type "localhost" into the form
    Then the "host" field contains "localhost"
    When I press Backspace
    Then the "host" field contains "localhos"

  @AC-002
  Scenario: Host, port and nickname each get their own labelled box
    Given the connect form is open
    Then host, port and nickname are each in their own titled box

  @AC-003
  Scenario: A nickname cannot contain whitespace
    Given the connect form is open
    When I focus the "nickname" field
    And I type "dave the" into the form
    Then the "nickname" field contains "davethe"

  @AC-003
  Scenario: A nickname stops accepting characters at the cap
    Given the connect form is open
    When I focus the "nickname" field
    And I type "davethegreatgatsby" into the form
    Then the nickname is capped at 10 characters
    And the "nickname" field contains "davethegre"
    When I type "x" into the form
    Then the "nickname" field contains "davethegre"

  @AC-004
  Scenario: The port field ignores anything that is not a digit
    Given the connect form is open
    When I focus the "port" field
    And I type "8a0b0" into the form
    Then the "port" field contains "800"

  @AC-005 @TB-012
  Scenario: The identity store path is prefilled but still mine to change
    Given the connect form is open
    Then the id_store path is prefilled with the default idstore location
    When I focus the "id_store" field
    And I clear the "id_store" field
    And I type "/tmp/my_ids_store" into the form
    Then the "id_store" field contains "/tmp/my_ids_store"
    When I press Backspace
    Then the "id_store" field contains "/tmp/my_ids_stor"

  @AC-070
  Scenario: my_key defaults to pq_hybrid, this app's strongest identity
    Given the connect form is open
    Then my_key defaults to pq_hybrid

  @AC-007 @TB-006
  Scenario: A completed form connects
    Given the connect form is open
    And the connect form is filled in with valid details
    And my_key is set to none
    Then a visible Connect button is offered
    And the request carries no key material for either key
    When I submit the form
    Then connecting begins with the details I entered

  @AC-008 @TB-005
  Scenario: An empty form refuses to connect and says why
    Given the connect form is open
    When I submit the form
    Then connecting is refused with an error mentioning "host"

  @AC-008 @TB-005
  Scenario Outline: Each missing piece of the form is reported by name
    Given the connect form is open
    And the connect form is filled in with valid details
    And my_key is set to <my_key>
    When I clear the "<field>" field
    Then building the request fails mentioning "<message>"

    Examples:
      | field    | my_key | message  |
      | host     | none   | host     |
      | nickname | none   | nickname |
      | id_store | none   | id_store |

  @AC-009
  Scenario: Escape abandons the form
    Given the connect form is open
    When I press Escape
    Then the form is cancelled

  @AC-010
  Scenario: An rsa key field is filled from the in-app file browser
    Given the connect form is open
    And a directory holding one sub-directory and one file
    When I open the file browser on that directory and pick the file
    Then the picked file fills the server_key field

  @AC-011
  Scenario: The file browser retraces its own steps
    Given the connect form is open
    And a directory holding one sub-directory and one file
    Then a fresh browser has nowhere to step back or forward to
    When I walk into the sub-directory and back out again
    Then the browser can step back and then forward again

  @AC-093
  Scenario: The file browser scrolls to keep the selection visible
    Given the connect form is open
    And a directory holding more files than fit in the file browser popup
    When I open the file browser on that directory and select the last entry
    Then the last entry is visible in the file browser
    And the first entry has scrolled out of view

  @AC-012
  Scenario: The focused Connect button highlights its label, not its frame
    Given the connect form is open
    And the connect form is filled in with valid details
    When I focus the "Connect" field
    Then the focused Connect button is highlighted but its border is not
