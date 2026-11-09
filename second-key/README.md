# second-key

A two-person rule for shared Hermes bots.

When Hermes wants to run a dangerous command, second-key sends the approval to the people on your roster by Telegram DM. The person whose message started the turn can never approve it. Critical commands need two approvals. If nobody answers, or something breaks, the command does not run.

```
Priya (in the team group):  @hermes clean up the old build volumes
Hermes:                     needs approval to run  rm -rf /srv/builds/2024-*
Priya taps Approve:         "Not counted: you cannot vote on this request."
Dev gets a DM, taps Approve once
Hermes runs the command, once.
```

## Why

Hermes asks before it runs a flagged command. In a group chat, the person who asked is usually the one who answers. Core's `approvals.approvers` setting decides who else may answer, and the requester can always answer their own request.

second-key reverses that. The requester is excluded, a quorum of other people decides, and every decision lands in a hash-chained ledger.

| | requester can approve own request | approvals needed | where approvers answer |
|---|---|---|---|
| Hermes built-in prompt | yes | 1 | the chat that asked |
| `approvals.approvers` (core) | yes | 1 | the chat that asked |
| second-key | **never** | 1, or 2 for critical commands and unknown requesters | private Telegram DM |

## How it works

1. `pre_approval_request` runs on the agent's own thread, where the turn's sender is bound. second-key records the sender's platform and user id against the request id.
2. Hermes hands the redacted request to the `secondkey` approval transport on a worker thread. second-key works out how many approvals it needs and who is eligible: the roster minus the requester.
3. Each eligible approver gets a DM with the command, the reason Hermes gave, who asked, and **Approve once** / **Deny** buttons.
4. A vote counts only when Telegram reports it came from an eligible approver. One deny closes the request. Enough yes votes close it as approved.
5. The answer goes back to Hermes, which enforces it. second-key only ever returns `once` or `deny`, so no answer can turn into a standing permission.

Rules that decide the number of approvals, largest wins:

- `required` (default 1) for any flagged command
- `critical_required` (default 2) when the command matches one of `critical_patterns`
- `unknown_requester_required` (default 2) when the turn carries no sender id, for example a cron job or a local session

If the roster has fewer eligible people than the request needs, second-key denies at once and DMs nobody.

`/yolo` turns approvals off entirely, so second-key drops `/yolo` from anyone who is not on the roster before it reaches the agent.

## Setup

1. Create a bot with [@BotFather](https://t.me/BotFather) for second-key. Use a separate bot from your Hermes gateway bot: two programs reading one bot's updates conflict.
2. Put its token in your Hermes profile:
   ```
   hermes config set SECONDKEY_TELEGRAM_BOT_TOKEN <token>
   ```
   Hermes saves it to the profile's `.env`.
3. Each approver opens a DM with the bot and sends `/start`. The bot replies with their Telegram id.
4. Configure the plugin and select it as the approval transport:
   ```yaml
   plugins:
     entries:
       second-key:
         settings:
           approvers:
             - { name: Priya, telegram_id: "111111111", aliases: ["discord:4242"] }
             - { name: Dev,   telegram_id: "222222222" }
             - { name: Sam,   telegram_id: "333333333" }
           required: 1
           critical_required: 2
           critical_patterns: ['rm\s+-rf', 'DROP\s+TABLE', 'terraform\s+destroy']
           unknown_requester_required: 2
   security:
     approval:
       transport: secondkey
   ```
   `aliases` lists the same person's ids on other chat platforms, so a request Priya starts from Discord is still hers.
5. Check it: `/secondkey` shows the policy and whether the token is set. `/secondkey ledger 20` shows recent decisions and whether the ledger chain is intact.

## The ledger

Every presentation, vote, refusal and decision is appended to `plugin-data/second-key/ledger.jsonl` in your Hermes home. Each line stores the SHA-256 of the line before it, so editing or deleting an earlier entry breaks the chain and `/secondkey ledger` reports the first broken line.

## What it touches

- **Network:** `api.telegram.org` only, with the bot token from `SECONDKEY_TELEGRAM_BOT_TOKEN`. Redirects are refused.
- **What approvers see:** the command after Hermes' own redaction, Hermes' reason for asking, and the requester's display name and platform.
- **Background thread:** one long-poll thread reads the bot's updates. It starts on the first approval or `/start` and runs until Hermes exits.
- **Files:** writes only its ledger under `plugin-data/second-key/`.
- **Credentials:** reads the bot token through `agent.secret_scope.get_secret`. It never reads `.env`, `auth.json` or any other credential store.
- **No telemetry, no self-updater, no shell commands, no dependencies beyond the standard library.**

## Tests

```
python -m unittest discover -s tests -t . -v
```

The suite drives the plugin through Hermes' real `ApprovalRequest` and `invoke_approval_transport` against a local Telegram Bot API server. It covers:

- the requester tapping Approve (denied on timeout)
- another approver approving
- an approver denying
- a critical command with one yes vote (denied)
- a critical command with two yes votes (approved)
- too few eligible approvers (denied, no DM sent)
- ledger tampering (chain reported broken)

Each guard was checked by breaking it and watching its test fail.
