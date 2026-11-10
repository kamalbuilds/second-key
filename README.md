# second-key

Team approvals for shared Hermes bots: dangerous commands need N votes from your roster, sized to the risk. The requester never counts, and an agent that edits its own approval settings is stopped on its next tool call. Ballots arrive as Telegram DMs.

![second-key architecture: tool call, approval gate, requester binding, quorum, Telegram ballots, votes, decision, hash-chained ledger](docs/architecture.svg)

Interactive version: [docs/architecture.html](docs/architecture.html).

## What it does

- Takes over Hermes' approval step with a transport named `secondkey`, so every flagged `terminal` command and `execute_code` script becomes a ballot.
- Excludes the requester by id and sends the ballot as a private DM to everyone else on the roster, with **Approve once** and **Deny** buttons.
- Sizes the quorum to the risk: `critical_required` yes votes for critical commands (`rm -rf`, `terraform destroy`, `git push --force`, `drop table` and more) and `unknown_requester_required` for requesters it cannot identify, two each by default. One deny closes the request.
- Answers Hermes with `once` or `deny` only. Silence, errors and too few approvers are a deny.
- Writes every presentation, vote and decision to a hash-chained ledger and puts the first 16 characters of the decision hash in each approver's closing DM.
- Stops the agent's tools when the approval settings change after arming, and refuses `/yolo` and `/approvals` from chats.

## Example

A real session: Hermes 0.23.1, `rm -rf /tmp/sk-critical`, two approvers on their phones.

```
07:37:30 presented   required 2 (critical pattern rm -rf), delivered to 2 approvers
07:37:34 vote        Kaveri 8840616281 -> counted ("Vote counted. Waiting for another approver.")
07:37:58 vote        Kamal 1478060433  -> approved
07:37:58 decided     once  (the command ran; /tmp/sk-critical removed)
```

A closing DM from the same live session (single-approval run), with the ledger hash approvers keep:

```
Approved once by Kaveri.

rm -r /tmp/***

ledger 6c07cc4ddf3d1484
```

## Install

```sh
hermes plugins install kamalbuilds/second-key/second-key --enable
```

Setup, the roster format, guard coverage, the ledger and what the plugin touches are in the [plugin README](second-key/README.md).

## Tests

```sh
python -m unittest discover -s tests -t . -v
```

## License

MIT
