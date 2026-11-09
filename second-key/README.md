# second-key

A two-person rule for shared Hermes bots.

When Hermes wants to run a dangerous command, second-key sends the approval to the people on your roster by Telegram DM. The person whose message started the turn can never approve it. Critical commands need two approvals. If nobody answers, or something breaks, the command does not run.

```
Priya (in the team group):  @hermes tear down the staging stack
Hermes:                     needs approval to run  terraform destroy -auto-approve
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

1. `pre_approval_request` runs on the agent's own thread, where the turn's sender is bound. second-key records the sender (`HERMES_SESSION_ACTOR_ID`, which is set in shared group chats too) against the request id.
2. Hermes hands the redacted request to the `secondkey` approval transport on a worker thread. second-key works out how many approvals it needs and who is eligible: the roster minus the requester.
3. Each eligible approver gets a DM with the command, the reason Hermes gave, who asked, and **Approve once** / **Deny** buttons.
4. A vote counts only when Telegram reports it came from an eligible approver. One deny closes the request. Enough yes votes close it as approved.
5. The answer goes back to Hermes, which enforces it. second-key only ever returns `once` or `deny`, so no answer can turn into a standing permission.

Rules that decide the number of approvals, largest wins:

- `required` (default 1) for any flagged command
- `critical_required` (default 2) when the command matches one of `critical_patterns`
- `unknown_requester_required` (default 2) when the turn carries no sender id, for example a cron job or a local session

second-key denies at once, and DMs nobody, when:

- the roster has fewer eligible people than the request needs
- a chat turn carries no sender id, or the sender is Telegram's anonymous group admin
- the command is longer than 3,000 characters, so approvers could not read all of it in one message

## What it guards

- **Commands:** dangerous terminal commands and `execute_code` scripts that Hermes sends to its approval transport.
- **Chat commands:** `/yolo` and `/approvals` switch approvals off or down for the whole profile, so second-key drops them from every chat before they reach Hermes. The profile owner changes them from the local CLI.
- **The agent editing its own guard:** a `pre_tool_call` hook refuses terminal, `execute_code` and file-write calls that touch `hermes config`, `hermes plugins`, `config.yaml`, the profile `.env` or second-key's settings, and file writes under `~/.ssh`.

Hermes asks for some other approvals (protected file writes, computer use, MCP elicitation) on its own chat prompts, which do not go through approval transports. `/secondkey` checks whether second-key is actually armed: selected as the transport, no builtin fallback, and `approvals.mode` not `off` or `smart`.

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
           critical_patterns: ['rm\s+-\w*(rf|fr)', 'rm\s+-r\s+-f', 'rm\s+-f\s+-r', 'drop\s+(table|database)', 'terraform\s+destroy']
           unknown_requester_required: 2
   security:
     approval:
       transport: secondkey
   ```
   `aliases` lists the same person's ids on other chat platforms, so a request Priya starts from Discord is still hers. Critical patterns match case-insensitively.
5. Check it: `/secondkey` shows whether second-key is armed, the policy, and whether the token is set. `/secondkey ledger 20` shows recent decisions and whether the ledger chain is intact.

## The ledger

Every presentation, vote, refusal, refused chat command, refused tool call and decision is appended to `plugin-data/second-key/ledger.jsonl` in your Hermes home. Each line stores the SHA-256 of the line before it, so editing or deleting an entry before the last one breaks the chain and `/secondkey ledger` reports the first broken line.

## What it touches

- **Network:** `api.telegram.org` only, with the bot token from `SECONDKEY_TELEGRAM_BOT_TOKEN`. Redirects are refused.
- **What approvers see:** the command after Hermes' own redaction, Hermes' reason for asking, and the requester's display name and platform.
- **Background thread:** one long-poll thread reads the bot's updates. It starts on the first approval or `/start` and runs until Hermes exits.
- **Files:** writes only its ledger under `plugin-data/second-key/`. Reads Hermes' `config.yaml` (read-only) for the `/secondkey` arming check.
- **Credentials:** reads the bot token through `agent.secret_scope.get_secret`. It never reads `.env`, `auth.json` or any other credential store.
- **No telemetry, no self-updater, no shell commands, no dependencies beyond the standard library.**

## Tests

```
python -m unittest discover -s tests -t . -v
```

The suite drives the plugin through Hermes' real `ApprovalRequest`, `invoke_approval_transport`, `set_session_vars` and `MessageEvent` parser, against a local Telegram Bot API server. It covers:

- the requester tapping Approve (denied on timeout)
- another approver approving
- an approver denying
- a critical command with one yes vote (denied)
- a critical command with two yes votes (approved)
- too few eligible approvers (denied, no DM sent)
- ledger tampering (chain reported broken)
- shared-group turns where only the actor id is set
- `/approvals off`, `/yolo` from an approver, and `/yolo` behind an attachment line
- the agent running `hermes config set approvals.mode off` or writing `config.yaml` or `~/.ssh/config`

Each guard was checked by breaking it and watching its test fail.
