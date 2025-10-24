# Project: tsidp

## Project Description:

`tsidp` is an OIDC / OAuth Identity Provider (IdP) server that integrates with your Tailscale network. It allows you to use Tailscale identities for authentication into applications that support OpenID Connect as well as authenticated MCP client / server connections.

## Tech stack

- golang
- html and javascript (ui.go)

## Testing

- `make test-dev` - runs all unit tests on code

## Workflow Tasks

### Plan Improvements

Work plans are located in ai-plans/. Plans written by the user may be incomplete, contain inconsistencies or errors.

When the user asks to improve a plan follow these guidelines for expanding and improving it.

- Identify any inconsistencies.
- Expand plans out to be detailed specification of requirements and changes to be made.
- Plans should have at least these sections:
  - Title - very short, describes changes
  - Overview: A more detailed summary of goal and outcomes desired
  - Design Requirements: Detailed descriptions of what needs to be done
  - Testing Plan: Tests to be implemented
  - Checklist: A detailed list of changes to be made

Look for "plan expansion" as explicit instructions to improve a plan.

### Implementation of plans

When the user says "paint it", respond with "commencing automated assembly". Then implement the changes as described by the plan. Update the checklist as you complete items.

## General Rules

- when summarizing changes only include details that require further action (action items)
- when there are no action items, just say "Done."
