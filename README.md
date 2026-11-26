# Countersign

**The brakes and the reverse gear for AI agents.**

## The problem

**AI agents are ready to do real work. Teams aren't ready to let them.**

- **Give an agent real access,** and one wrong step, or one instruction hidden in an email, does damage that can't be undone.
- **Make a person approve every step,** and the agent is slow, and after the fiftieth pop-up nobody reads what they approve.

So most agents stay read-only.

## The solution

**AI is the driver. Countersign is the brakes.** And the reverse gear.

Countersign sits between your agents and the systems they touch, so agents can move fast without anything going wrong for good.

- ✅ Agents work at full speed on a staged copy
- ✅ Only steps that can't be undone wait for a person
- ✅ Anything can be undone, even after it lands

## How it works

Every task is a transaction.

1. **Stage.** Database writes, file edits, shell commands, pushes and cloud changes are staged. Messages wait in an outbox. Your real systems don't move while the agent works.
2. **Preview.** One preview shows every row, file and resource the task would change, checked by the real systems before anything is real.
3. **Approve.** Payments, mass deletes and messages to people nobody asked for wait for the right reviewer. Each decision is signed with that person's own key, and nobody can approve their own request.
4. **Commit or undo.** The whole task lands as one unit. Undo puts back exactly what the task changed and keeps what everyone else did since.

## An engine, not another AI

Countersign doesn't ask a model whether something is safe. Every decision comes from the systems that actually know: your database counts the rows a change hits, your cluster validates the change, your cloud permissions say what is a write, and the operating system confines the agent's shell. The same action gets the same answer every time, in milliseconds. It doesn't need an LLM.

## Results

- **Prompt injection attacks cut from 43.4% to 3.4%** on [AgentDojo](https://github.com/ethz-spylab/agentdojo), the standard benchmark for agents under prompt injection.
- **Tested with real Claude Code:** work committed, risky moves held, secrets kept from the agent.
- **200 forced crashes:** every task all or nothing.
- **30 agents at once:** no lost or overwritten work.

## What it covers

| | |
|---|---|
| **AWS** | Create and update cloud resources, undoable. Your IAM decides what counts as a change. Secrets never reach the agent. Terraform applied on commit. Deletes wait for a person. |
| **Kubernetes** | Your cluster validates every change first. Undo keeps the autoscaler's work. Whole namespaces come back. Data-destroying deletes need a person. |
| **Databases** | PostgreSQL and SQLite. Changes are invisible until commit, with exact undo even after commit. Many agents at once, no overwrites. |
| **Code and git** | A sandboxed shell on a private copy. Pushes you can take back. Keys and `.env` files never leave. |
| **Any SaaS** | One small TOML file per app. Messages go out on commit. Payments and unrequested recipients wait for a reviewer. |

## Plug it in

One small binary and one TOML file. Your agent keeps its tools; it just reaches the world through Countersign.

- **Any MCP agent** (Claude Code, Cursor, Claude Desktop): add it as an MCP server.
- **Fully confined:** run the agent inside Countersign, so its only way out is through it.
- **Python apps:** wrap the tools your app already has with one decorator.
- **Any SaaS API:** describe it once in a TOML file (see `registry/` for Stripe, Slack, Gmail and Google Calendar).

## Getting started

### Requirements

- Go 1.27 or newer
- Python 3.11 or newer (for the demo and the Python SDK)
- git

The command-line tool is called `undolayer`.

### 1. Build

```sh
git clone https://github.com/SagarMSalgar/Countersign.git
cd Countersign
go build -o bin/undolayer ./cmd/undolayer
export PATH="$PWD/bin:$PATH"
```

### 2. Try the two-minute demo

No API key needed; you play the reviewer.

```sh
sh examples/quickstart/setup.sh
python3 examples/quickstart/demo.py /tmp/undolayer-demo
```

### 3. Write a config

`undolayer.toml`:

```toml
state_dir = ".undolayer"

[workspace]
root = "."            # the project the agent works on

[sql]
dsn = "app.db"        # SQLite file, or a postgres:// URL

[approvals]
wait = "5m"           # risky steps wait for a reviewer instead of failing
```

All options are documented in `internal/runtime/config.go`.

### 4. Connect your agent

**MCP agents (Claude Code, Cursor, Claude Desktop).** Add this to your project's `.mcp.json`:

```json
{ "mcpServers": { "undolayer": { "command": "undolayer", "args": ["connect"] } } }
```

`undolayer setup claude-code -c undolayer.toml` prints the exact setup for your machine.

**Fully confined.** Start the agent inside Countersign:

```sh
undolayer run -c undolayer.toml -- claude
```

**Python apps.**

```sh
pip install ./sdk/python
```

```python
from undolayer import Undolayer

ul = Undolayer(approver=my_review)

@ul.tool(lane="read")
def search_orders(customer: str) -> list: ...

@ul.tool(lane="irreversible", destinations=["iban"])   # a person approves first
def refund(iban: str, amount: float) -> dict: ...

with ul.session(user_request) as s:
    s.call("refund", iban="...", amount=40)
# commits on exit; any exception rolls everything back
```

More in `sdk/python/README.md`.

### 5. Review, approve and undo

```sh
undolayer pending -c undolayer.toml                     # what is waiting for a person
undolayer approve <tx> -c undolayer.toml                # approve a task's preview
undolayer approve <tx> --action <id> --decline          # decline one action
undolayer undo <tx>                                     # undo a committed task
```

To have named reviewers sign decisions with their own keys:

```sh
undolayer reviewer keygen alice
```

### Get the full record of any task

Every approval and decline keeps a copy of exactly what the reviewer was shown, in the tamper-evident audit log. It stays there after the task commits, is undone, or fails.

```sh
undolayer evidence <tx> --out evidence.json -c undolayer.toml
```

One JSON document with everything about the task: what was asked, every action and its decision, what each reviewer approved or declined and what they saw, the before-state that undo restores (kept even after an undo), the outbox, every audit event, and whether the audit chain is intact.

### Learn from your reviewers

Countersign can train a small risk model on the decisions your reviewers have already made, so actions that look like ones they declined before get flagged automatically.

```sh
undolayer risk train -c undolayer.toml               # learns from approvals and declines in the audit log
undolayer risk explain <tx> -c undolayer.toml        # each action's score and the features behind it
```

Then point the config at the model and add a rule on its score:

```toml
[risk]
model = "risk-model.json"
```

```toml
[[rule]]
id = "learned-risk"
decision = "require_approval"
reason = "reviewers have declined actions like this"
when = { risk_score = { gt = 0.85 } }
```

The model scores the same action the same way every time, explains each score, and adds caution where your reviewers were cautious. Rules only escalate, so it can never remove a check. You can also train on your own labelled data with `--data examples.jsonl`, one `{"action": {...}, "label": 0 or 1}` per line.

### Add any SaaS API

```sh
undolayer registry test registry/stripe.toml -c undolayer.toml
```

A registry file describes an API's actions and how each one is undone. Use the files in `registry/` as templates.
