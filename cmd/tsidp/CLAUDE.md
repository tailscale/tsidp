## New layout

legacy/tsidp.go will be refactored into this new app structure:

```
tsidp-server.go
server/ - http web server and handlers
oauth/ - OAuth functionality
```

## TODOFILE

- the TODOFILE is 02-migration-parity-todo.txt.
- the TODOFILE contains a list tasks that need to be completed

## Refactoring Rules

- tests should be migrated with functionality into appropriate packages
- leave files in legacy/ alone
- add comments in new source files to location in legacy/ code it was migrated from
- require the user to request an item from the TODOFILE before working on it
- only start working on a task when the user has explicitly given instructions to start
- when the user asks questions about a task in TODO, use the code as a reference and provide succinct answers

## Testing

- use `make test` to run tests
- run tests after changes

# Goals

- refactor legacy/tsidp.go into tsidp-server.go and smaller packages
- complete items in TODOFILE
