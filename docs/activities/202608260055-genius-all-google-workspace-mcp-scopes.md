# Genius all-Google-Workspace MCP grant

The central `google-workspace` integration grant now covers the eight services
published by Google's Workspace MCP guide: Gmail, Drive, Docs, Sheets, Slides,
Calendar, Chat and People. The additional grant includes Sheets, Slides, five
Chat capabilities, domain directory, contacts and Gmail compose access.

The contract stays subject-bound. Provider refresh tokens remain encrypted in
`user-<sub>`, Genius receives only short-lived execution headers, and users are
never asked for a client id, secret or pasted OAuth token. Existing grants are
detected as stale through the persisted provider scope list and are renewed by
the same browser flow.

The registry test asserts the complete scope surface so adding a catalog card
without its central authorization fails CI.
