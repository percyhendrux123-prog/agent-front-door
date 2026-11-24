# Undo

Running the door locally changes nothing outside this folder.

- Runtime state (owner channel, owner inbox, receipts): delete `.state/`, `demo/state/` and `demo/state-client/`. All three are git-ignored and never committed.
- Python dependencies (mcp, pyyaml) live only in this repo's `.venv`; delete it to remove them.
- The door sends nothing, books nothing and takes no money, so there is nothing outside to roll back.

## Hosted door (worker/ and owner/)

- Stop the owner side: `launchctl bootout gui/$(id -u)/ai.axiom.front-door-owner` (or whatever label you gave it). Its state is one folder (`AFD_STATE_DIR`); the token is one file.
- Close the owner side without taking the door down: `npx wrangler secret delete OWNER_TOKEN_SHA256` (owner endpoints then answer 401).
- Back to the read-only door: `npx wrangler rollback <previous version id>`.
- Take the door down: `cd worker && npx wrangler delete --name <worker name>` (this also removes the Durable Object's data).
