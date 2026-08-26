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
    Then the nickname is capped at 11 characters
    And the "nickname" field contains "davethegrea"
    When I type "x" into the form
    Then the "nickname" field contains "davethegrea"

  @AC-004
  Scenario: The port field ignores anything that is not a digit
    Given the connect form is open
    When I focus the "port" field
    And I type "8a0b0" into the form
    Then the "port" field contains "800"

  @AC-005
  Scenario: There is no id_store field to fill in
    Given the connect form is open
    Then the form has no id_store field

  @AC-269
  Scenario: The password field is masked
    Given the connect form is open
    When I focus the "password" field
    And I type "hunter2" into the form
    Then the "password" field contains "hunter2"
    But the password field is shown masked

  @AC-269
  Scenario: ssl is not a popup field - it defaults off, as connect_using_ssl settings say
    Given the connect form is open
    Then ssl is off
    And the form has no ssl field

  @AC-070 @AC-010
  Scenario: my_key is pq_hybrid, shown read-only, with no type to choose
    Given the connect form is open
    Then my_key is pq_hybrid with no type to choose

  @AC-258
  Scenario: The form names the ALOO_HOME this client is actually using
    Given the connect form is open
    Then the form shows the ALOO_HOME it resolved, in gray

  @AC-007 @TB-006
  Scenario: A completed form connects
    Given the connect form is open
    And the connect form is filled in with valid details
    And my_key points at a keybundle pair
    Then a visible Connect button is offered
    And the request carries the details as typed
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
    And my_key points at a keybundle pair
    When I clear the "<field>" field
    Then building the request fails mentioning "<message>"

    Examples:
      | field    | message  |
      | host     | host     |
      | nickname | nickname |
      | password | password |

  @AC-270
  Scenario: The registration fields are always on screen, on any server
    Given the connect form is open
    Then an email field and a Register button are offered

  @AC-270
  Scenario: Register needs an email that Connect does not
    Given the connect form is open
    And the server allows registration
    And the connect form is filled in with valid details
    When I focus the "Register" field
    Then registering is refused with an error mentioning "email"
    When I focus the "email" field
    And I type "dave@example.com" into the form
    And I focus the "Register" field
    Then registering begins with the email I entered

  @AC-270 @AC-271
  Scenario: A successful registration opens the activation popup directly
    Given the connect form is open
    And the server allows registration
    And the connect form is filled in with valid details
    When I focus the "email" field
    And I type "dave@example.com" into the form
    And I focus the "Register" field
    Then registering begins with the email I entered
    And a successful registration opens the activation popup with "Enter the activation code you received by email"

  @AC-270
  Scenario: A server that does not allow registration refuses Register, in red, only when pressed
    Given the connect form is open
    And the connect form is filled in with valid details
    When I focus the "email" field
    And I type "dave@example.com" into the form
    And I focus the "Register" field
    Then registering is refused with an error mentioning "does not accept registrations"

  @AC-009
  Scenario: Escape abandons the form
    Given the connect form is open
    When I press Escape
    Then the form is cancelled

  @AC-012
  Scenario: The focused Connect button highlights its label, not its frame
    Given the connect form is open
    And the connect form is filled in with valid details
    When I focus the "Connect" field
    Then the focused Connect button is highlighted but its border is not

  @AC-240
  Scenario: The form comes back as whoever connected last
    Given a settings file recording a connection as "dave" to "chat.example.com" port 6667
    When the connect form opens on that machine
    Then the "nickname" field contains "dave"
    And the "host" field contains "chat.example.com"
    And the "port" field contains "6667"

  @AC-240
  Scenario: A machine that has never connected proposes the local user
    Given a settings file with no connection recorded
    When the connect form opens on that machine
    Then the "nickname" field contains "whoami"
