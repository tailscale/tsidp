# Title: Consolidate OAuth Client Management to Use /clients API Endpoints

## Overview

This plan addresses [issue #78](https://github.com/tailscale/tsidp/issues/78): Consolidate endpoints for managing OAuth clients.

Currently, there are two parallel systems for managing `IDPServer.funnelClients`:

1. **Admin UI** (served under `/`) - Uses server-side rendered HTML with form POST to `/new` and `/edit/{id}` endpoints that directly manipulate `funnelClients` data
2. **API endpoints** (served under `/clients`) - RESTful JSON API with GET, POST, and DELETE operations

The `/clients` API was implemented first and provides a clean, well-tested interface. The UI was added later and introduced duplicate logic for client mutations. This creates maintenance overhead, potential for bugs, and inconsistency.

**Goal**: Refactor the UI to use the existing `/clients` API endpoints via client-side JavaScript, eliminating duplicate server-side mutation logic while preserving the user experience.

**Outcomes**:
- Single source of truth for client mutations (`/clients` API)
- Reduced code complexity and maintenance burden
- Preserved HTML templates and UI styling
- All existing tests continue to pass
- API contract of `/clients` endpoints remains unchanged

## Current State Analysis

### Existing API Endpoints (/clients)

Located in [server/clients.go](../server/clients.go):

1. **GET /clients** (serveGetClientsList:208-228)
   - Returns JSON array of all clients
   - Secrets are omitted from response
   - Requires tailnet access (blocked over funnel)

2. **POST /clients/new** (serveNewClient:166-204)
   - Creates new client from form data
   - Expects: `name` and `redirect_uri` (newline-separated)
   - Returns: Full client object including secret
   - Generates random client_id and client_secret
   - Persists to disk via `storeFunnelClientsLocked()`

3. **GET /clients/{id}** (serveClients:149-162)
   - Returns single client by ID
   - Secret is omitted from response

4. **DELETE /clients/{id}** (serveDeleteClient:232-270)
   - Deletes client by ID
   - Cleans up associated tokens (code, accessToken, refreshToken)
   - Returns 204 No Content on success

### Existing UI Endpoints (/)

Located in [server/ui.go](../server/ui.go):

1. **GET /** (handleClientsList:84-110)
   - Server-rendered list of clients using `ui-list.html` template
   - Displays client name, ID, redirect URIs, status, and edit button

2. **GET /new** (handleNewClient:114-186)
   - Shows empty form using `ui-edit.html` template

3. **POST /new** (handleNewClient:122-182)
   - Creates client directly in handler
   - Duplicates logic from `serveNewClient`
   - Generates client_id and client_secret inline
   - Persists via `storeFunnelClientsLocked()`
   - Re-renders form with success message and displays secret

4. **GET /edit/{id}** (handleEditClient:189-217)
   - Shows populated form using `ui-edit.html` template

5. **POST /edit/{id}** (handleEditClient:219-320)
   - Handles three actions:
     - `action=delete`: Deletes client (duplicates `/clients/{id}` DELETE logic)
     - `action=regenerate_secret`: Regenerates client secret
     - Default: Updates name and redirect_uris
   - All mutations directly access `s.funnelClients` and call `storeFunnelClientsLocked()`

### Identified Inconsistencies

1. **Missing UPDATE endpoint**: The `/clients` API has no PUT/PATCH endpoint for updating client name and redirect URIs, but the UI needs this functionality

2. **Secret regeneration**: The UI supports regenerating secrets (`action=regenerate_secret`), but this functionality doesn't exist in `/clients` API

3. **Response format mismatch**:
   - API returns JSON with secrets included on creation
   - UI needs to display secrets immediately after creation
   - API omits secrets on GET requests (security feature)

4. **Error handling**:
   - UI renders errors in HTML form with error messages
   - API returns HTTP status codes with JSON error objects
   - Need JavaScript to translate API responses into UI feedback

5. **Form data vs JSON**:
   - Current UI uses `application/x-www-form-urlencoded` form submissions
   - `/clients` API expects form data for POST /clients/new but returns JSON
   - Need to handle both in JavaScript

## Design Requirements

### DR-1: Extend /clients API with Missing Operations

Add the following endpoints to [server/clients.go](../server/clients.go):

1. **PUT /clients/{id}** - Update existing client
   - Method: PUT
   - Content-Type: application/x-www-form-urlencoded (matches POST /clients/new)
   - Parameters:
     - `name` (string, optional): Client display name
     - `redirect_uri` (string, required): Newline-separated redirect URIs
   - Response: 200 OK with updated client JSON (secret omitted)
   - Errors:
     - 400 if redirect_uri is empty or invalid
     - 404 if client_id not found
     - 500 if persistence fails
   - Side effects: Calls `storeFunnelClientsLocked()`

2. **POST /clients/{id}/regenerate-secret** - Regenerate client secret
   - Method: POST
   - No body required
   - Response: 200 OK with client JSON including new secret
   - Errors:
     - 404 if client_id not found
     - 500 if persistence fails
   - Side effects:
     - Generates new secret via `generateClientSecret()`
     - Updates `s.funnelClients[clientID].Secret`
     - Calls `storeFunnelClientsLocked()`
     - Invalidates existing tokens (optional enhancement)

### DR-2: Convert UI Templates to Use Client-Side JavaScript

Modify existing HTML templates to use fetch API for AJAX calls:

#### DR-2.1: Update [server/ui-list.html](../server/ui-list.html)
- Keep existing template structure (lines 1-83)
- Template continues to render initial page server-side
- No changes needed - list page is read-only

#### DR-2.2: Update [server/ui-edit.html](../server/ui-edit.html)

Add JavaScript at the end (before `</body>`) to:

1. **Intercept form submission** (lines 69-132)
   - Prevent default form POST behavior
   - Use `fetch()` to call appropriate `/clients` API endpoint
   - Handle loading states (disable submit button, show spinner)

2. **Handle create client** (form on /new)
   - POST to `/clients/new` with FormData
   - On success (200):
     - Extract client_id and client_secret from JSON response
     - Display success message
     - Show client_id and client_secret in readonly fields
     - Update page state to show created client (keep form visible with secrets)
   - On error (4xx/5xx):
     - Parse JSON error response
     - Display error message in `.alert-error` div

3. **Handle update client** (form on /edit/{id})
   - PUT to `/clients/{id}` with FormData
   - On success (200):
     - Display success message in `.alert-success` div
     - Update page content if needed
   - On error (4xx/5xx):
     - Display error message in `.alert-error` div

4. **Handle regenerate secret** (button with `name="action" value="regenerate_secret"`)
   - POST to `/clients/{id}/regenerate-secret`
   - Confirm action before proceeding (keep existing confirm dialog)
   - On success (200):
     - Extract new secret from JSON response
     - Show `.secret-display` section with new secret
     - Display success message
   - On error (4xx/5xx):
     - Display error message

5. **Handle delete client** (button with `name="action" value="delete"`)
   - DELETE to `/clients/{id}`
   - Confirm action before proceeding (keep existing confirm dialog)
   - On success (204):
     - Redirect to `/` (client list)
   - On error (4xx/5xx):
     - Display error message

6. **Error message formatting**
   - Parse JSON error responses: `{"error": "code", "error_description": "message"}`
   - Display `error_description` in user-friendly format
   - Show generic "An error occurred" message if parsing fails

7. **Keep existing copy button functionality** (lines 154-195)
   - No changes needed to `copySecret()` and `copyClientId()` functions

### DR-3: Remove Duplicate Mutation Logic from ui.go

Modify [server/ui.go](../server/ui.go):

1. **Keep `handleUI` router function** (lines 45-80)
   - Still serves HTML templates
   - Still handles authorization checks

2. **Simplify `handleNewClient`** (lines 114-186)
   - **GET /new**: Keep as-is (renders empty form)
   - **POST /new**: REMOVE entirely (lines 122-182)
   - Form submission will be handled by JavaScript calling POST /clients/new

3. **Simplify `handleEditClient`** (lines 189-320)
   - **GET /edit/{id}**: Keep as-is (renders populated form)
   - **POST /edit/{id}**: REMOVE entirely (lines 219-320)
   - All mutations (update, delete, regenerate) handled by JavaScript

4. **Keep helper functions**:
   - `renderClientForm` (lines 338-347) - still needed for GET requests
   - `renderFormError` (lines 351-356) - REMOVE (errors now shown via JavaScript)
   - `renderFormSuccess` (lines 360-365) - REMOVE (success now shown via JavaScript)
   - `clientDisplayData` struct (lines 324-334) - keep but Success/Error fields no longer used

5. **Keep `validateRedirectURI`** (lines 368-379)
   - Still used by API endpoints
   - Could be called client-side as additional validation (optional enhancement)

### DR-4: Maintain API Contract Compatibility

Ensure no breaking changes to existing `/clients` API:

1. All existing endpoints maintain same:
   - URL paths
   - HTTP methods
   - Request/response formats
   - Status codes
   - Error response structure

2. New endpoints follow existing patterns:
   - Same authentication/authorization checks (`isFunnelRequest` blocked)
   - Same error handling via `writeHTTPError`
   - Same mutex locking patterns (`s.mu.Lock()`)
   - Same persistence mechanism (`storeFunnelClientsLocked()`)

3. Response JSON uses same field names:
   - `client_id`, `client_secret`, `client_name`, `redirect_uris`, etc.
   - Matches `FunnelClient` struct JSON tags (lines 20-40 in clients.go)

### DR-5: Security Considerations

1. **Authorization**: All endpoints remain protected by application capability checks
2. **Funnel blocking**: All mutation endpoints remain blocked over funnel
3. **Secret exposure**: Secrets only returned on creation and regeneration (not on GET)
4. **CSRF protection**: Not currently implemented, but form-based approach had same exposure
5. **Input validation**: Maintain existing validation for redirect URIs

### DR-6: Backward Compatibility

1. **Direct API access**: External tools/scripts using `/clients` API continue to work unchanged
2. **Template structure**: HTML templates remain compatible with existing CSS (ui-style.css)
3. **URLs**: All UI URLs (`/`, `/new`, `/edit/{id}`) remain the same
4. **Session data**: No session/state management required (stateless API calls)

## Testing Plan

### TP-1: Unit Tests for New API Endpoints

Add to [server/client_test.go](../server/client_test.go):

1. **TestServeUpdateClient**
   - Test updating client name and redirect URIs
   - Test validation errors (empty redirect_uri, invalid URIs)
   - Test updating non-existent client (404)
   - Test persistence by loading from disk
   - Test that secret is NOT included in response

2. **TestServeRegenerateSecret**
   - Test regenerating secret for existing client
   - Test that new secret is different from old secret
   - Test that secret IS included in response
   - Test regenerating for non-existent client (404)
   - Test persistence by loading from disk
   - Verify old secret is replaced

3. **TestClientAPIRouting**
   - Verify PUT /clients/{id} routes to update handler
   - Verify POST /clients/{id}/regenerate-secret routes correctly
   - Test method validation (405 errors)

### TP-2: Integration Tests for UI with JavaScript

Add to [server/ui_test.go](../server/ui_test.go):

**TestUIRouting**
- Verify GET / still returns HTML
- Verify GET /new returns HTML form
- Verify GET /edit/{id} returns HTML form

**FYI - Manual browser testing checklist** (no code required):
- Create new client via UI
- Verify client_id and client_secret are displayed
- Verify client appears in list
- Edit client name and redirect URIs
- Verify changes are saved
- Regenerate secret
- Verify new secret is displayed
- Delete client
- Verify redirect to list and client is gone
- Test error scenarios (invalid redirect URI, network errors)

### TP-3: Regression Testing

Run existing tests: `make test-dev`
- All tests in `client_test.go` should pass (existing functionality plus new endpoint tests)
- All tests in `ui_test.go` should pass (routing and rendering still work)
- New API endpoint tests from TP-1 provide coverage for PUT and POST regenerate-secret

### TP-4: End-to-End Testing

**FYI - Manual test scenarios** (no code required):

1. Start fresh server with no clients
2. Navigate to UI in browser
3. Create first client → verify success message and secrets shown
4. Return to list → verify client appears
5. Edit client → change name and add redirect URI → verify success
6. Regenerate secret → verify new secret shown
7. Copy secret button → verify copies to clipboard
8. Delete client → verify confirmation and removal
9. Test validation errors:
   - Try to create/update client with empty redirect URI
   - Try to update non-existent client (should not be possible via UI)

## Detailed Checklist

### Phase 1: Extend API Endpoints
- [x] Add `serveUpdateClient` function to [server/clients.go](../server/clients.go)
  - [x] Parse form data (name, redirect_uri)
  - [x] Validate redirect URIs using `splitRedirectURIs` and `validateRedirectURI`
  - [x] Update `s.funnelClients[clientID]` with new values
  - [x] Call `s.storeFunnelClientsLocked()`
  - [x] Return updated client JSON (without secret)
  - [x] Handle errors (404 for not found, 400 for validation, 500 for storage)

- [x] Add `serveRegenerateSecret` function to [server/clients.go](../server/clients.go)
  - [x] Generate new secret via `generateClientSecret()`
  - [x] Update `s.funnelClients[clientID].Secret`
  - [x] Call `s.storeFunnelClientsLocked()`
  - [x] Return client JSON with new secret included
  - [x] Handle errors (404 for not found, 500 for storage)

- [x] Update `serveClients` router function (line 123)
  - [x] Add handling for PUT method when client ID is in path
  - [x] Add handling for POST method with `/regenerate-secret` suffix
  - [x] Route to `serveUpdateClient` for PUT requests
  - [x] Route to `serveRegenerateSecret` for POST regenerate requests

### Phase 2: Add Unit Tests
- [x] Create `TestServeUpdateClient` in [server/client_test.go](../server/client_test.go)
  - [x] Test successful update with valid data
  - [x] Test update with empty redirect_uri (expect 400)
  - [x] Test update with invalid redirect URI (expect 400)
  - [x] Test update non-existent client (expect 404)
  - [x] Test persistence (create new server instance, verify changes saved)
  - [x] Verify secret not included in response

- [x] Create `TestServeRegenerateSecret` in [server/client_test.go](../server/client_test.go)
  - [x] Test successful regeneration
  - [x] Verify new secret different from old
  - [x] Verify new secret included in response
  - [x] Test regenerate for non-existent client (expect 404)
  - [x] Test persistence

- [x] Run `make test-dev` and ensure all tests pass

### Phase 3: Update UI Templates with JavaScript
- [x] Modify [server/ui-edit.html](../server/ui-edit.html)
  - [x] Add `<script>` section before closing `</body>` tag
  - [x] Implement `handleFormSubmit` function:
    - [x] Prevent default form submission
    - [x] Detect context (create vs edit) from DOM
    - [x] Extract form data into FormData object
    - [x] Disable submit button during request
    - [x] Call appropriate API endpoint via fetch
    - [x] Handle success response
    - [x] Handle error response
    - [x] Re-enable submit button after completion

  - [x] Implement `handleCreate` function:
    - [x] POST to `/clients/new` with FormData
    - [x] On success: extract client_id and client_secret from JSON
    - [x] Update DOM to show success message
    - [x] Populate readonly fields with client_id and secret
    - [x] Show "Back to Clients" link prominently

  - [x] Implement `handleUpdate` function:
    - [x] Extract client ID from URL or form
    - [x] PUT to `/clients/{id}` with FormData
    - [x] On success: show success message
    - [x] On error: show error message

  - [x] Implement `handleRegenerateSecret` function:
    - [x] Triggered by button with `name="action" value="regenerate_secret"`
    - [x] Show confirm dialog (reuse onclick confirm)
    - [x] POST to `/clients/{id}/regenerate-secret`
    - [x] On success: show new secret in DOM
    - [x] Display success message

  - [x] Implement `handleDelete` function:
    - [x] Triggered by button with `name="action" value="delete"`
    - [x] Show confirm dialog (reuse onclick confirm)
    - [x] DELETE to `/clients/{id}`
    - [x] On success (204): redirect to `/`
    - [x] On error: show error message

  - [x] Implement `showError(message)` helper function:
    - [x] Find or create `.alert-error` div
    - [x] Set message text
    - [x] Show div (remove hidden class if needed)
    - [x] Clear any success messages

  - [x] Implement `showSuccess(message)` helper function:
    - [x] Find or create `.alert-success` div
    - [x] Set message text
    - [x] Show div
    - [x] Clear any error messages

  - [x] Wire up event listeners:
    - [x] Add submit event listener to form
    - [x] Add click event listeners to action buttons
    - [x] Ensure event listeners added after DOM load

### Phase 4: Simplify ui.go Server Handlers
- [x] Modify [server/ui.go](../server/ui.go)
  - [x] Update `handleNewClient` (line 114):
    - [x] Keep GET branch (lines 115-120) as-is
    - [x] Remove entire POST branch (lines 122-182)
    - [x] Add case to return 405 Method Not Allowed for POST

  - [x] Update `handleEditClient` (line 189):
    - [x] Keep GET branch (lines 205-217) as-is
    - [x] Remove entire POST branch (lines 219-320)
    - [x] Add case to return 405 Method Not Allowed for POST

  - [x] Remove `renderFormError` function (lines 351-356)
  - [x] Remove `renderFormSuccess` function (lines 360-365)
  - [x] Update `clientDisplayData` struct (lines 324-334):
    - [x] Remove `Success` field
    - [x] Remove `Error` field
    - [x] Keep all other fields

### Phase 5: Regression Testing
- [x] Run `make test-dev` to verify all unit tests pass
  - [x] All existing tests in `client_test.go` pass
  - [x] All existing tests in `ui_test.go` pass
  - [x] New tests from Phase 2 pass (TestServeUpdateClient, TestServeRegenerateSecret)
- [x] Verify API contract maintained through unit test coverage

### Phase 6: Manual UI Testing (FYI - no code to write)

Start development server and test in browser:
- Navigate to UI (/)
- Verify list displays correctly
- Click "Add New Client"
- Fill form and submit
- Verify success message shows
- Verify client_id and client_secret displayed
- Verify "Copy" buttons work
- Return to list
- Verify new client appears
- Click "Edit" on client
- Modify name and redirect URIs
- Submit form
- Verify success message
- Verify changes saved (refresh page)
- Click "Regenerate Secret"
- Confirm in dialog
- Verify new secret displayed
- Verify copy button works
- Click "Delete Client"
- Confirm in dialog
- Verify redirect to list
- Verify client removed from list

Test error scenarios:
- Try to create client with empty redirect URI
- Verify error message displays
- Try to create client with invalid redirect URI (e.g., "not-a-url")
- Verify error message displays
- Try to edit client with invalid data
- Verify error message displays

### Phase 7: Documentation Updates
- [ ] Update code comments in [server/clients.go](../server/clients.go) for new functions
- [ ] Update any relevant documentation mentioning the UI implementation
- [ ] Add JSDoc-style comments to JavaScript functions in templates

## Implementation Notes

1. **Order of implementation**: Follow phases sequentially to minimize breaking changes
2. **Testing between phases**: Run tests after each phase to catch issues early
3. **Rollback plan**: Keep original ui.go POST handlers commented out initially, remove after manual testing confirms everything works
4. **Browser compatibility**: Use fetch API (supported in all modern browsers), consider polyfill for older browsers if needed
5. **JavaScript location**: Inline in template vs separate file - inline is simpler for this use case and keeps templates self-contained
6. **Error handling**: Be specific in error messages to help users understand what went wrong
7. **Loading states**: Add visual feedback (disable buttons, show spinner) during async operations to improve UX

## Migration Path

This is not a breaking change for end users. Migration is seamless:

1. Deploy updated server binary
2. Existing clients in storage file are unchanged
3. UI URLs remain the same
4. API endpoints remain compatible
5. External API consumers unaffected
6. No data migration needed

## Success Criteria

- [x] All existing unit tests pass
- [x] All new unit tests pass
- [ ] Manual browser testing checklist completed (FYI - requires running dev server)
- [x] No duplicate client mutation code remains in ui.go
- [x] UI functionality is equivalent to before (users see no difference)
- [x] Code is cleaner and more maintainable
- [x] API endpoints follow RESTful conventions
