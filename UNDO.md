# Undo

Running the door locally changes nothing outside this folder.

- Runtime state (owner channel, owner inbox, receipts): delete `.state/`, `demo/state/` and `demo/state-client/`. All three are git-ignored and never committed.
- Python dependencies (mcp, pyyaml) live only in this repo's `.venv`; delete it to remove them.
- The door sends nothing, books nothing and takes no money, so there is nothing outside to roll back.
