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
| **AWS, Azure, Google Cloud** | Create and update cloud resources, undoable, with only what changed put back. Your cloud permissions decide what counts as a change. Secrets never reach the agent, and changes to secrets the cloud hides wait for a person. Anything opened to the whole internet waits for a person. Terraform applied on commit. Deletes wait for a person. |
| **Kubernetes** | Your cluster validates every change first. Undo keeps the autoscaler's work. Whole namespaces come back. Data-destroying deletes need a person. |
| **Databases** | PostgreSQL and SQLite. Changes are invisible until commit, with exact undo even after commit. Many agents at once, no overwrites. |
| **Code and git** | A sandboxed shell on a private copy. Pushes you can take back. Keys and `.env` files never leave. |
| **Any SaaS and HTTP API** | One small TOML file per app. Messages go out on commit. Payments and unrequested recipients wait for a reviewer. Every call is in the vault before it is sent. Agents can't reach cloud metadata services or private networks. |
| **Other MCP servers** | Their tools sit behind Countersign with the same policy, approval, vault and audit. Tool definitions are pinned, so a server can't quietly rewrite a tool. |
| **AI agents** | One command freezes an agent everywhere at once. |

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

### Keep every change's before state, in several copies

Before a change runs, what it will delete or overwrite is written to the vault. That covers every old row, dropped tables and columns, the bytes of every file changed or deleted, Kubernetes objects, cloud resource settings, branch heads, and the exact way back. The change runs only once a majority of the vault's replicas have it on disk. If they can't take it, the change doesn't run.

```toml
[vault]
replicas = ["/mnt/disk1/countersign", "/mnt/disk2/countersign", "/mnt/nfs/countersign"]
# write_quorum = 2                     (default: a majority)
# require_independent_replicas = true  (refuse replicas on the same disk)
# key_file = "/etc/countersign/vault.keys"
```

Without a `[vault]` section, one copy is kept in `state_dir/vault`.

- **Replicas.** Each replica is an append-only, checksummed hash chain. A replica that was down is caught up before it takes new writes, streamed in batches however far behind it is. A damaged replica is repaired from the others. Nothing is ever deleted: damaged or out-of-place records are moved aside, and reads still find them. `vault check` warns when replicas share a disk.
- **Encryption.** What the vault holds is encrypted with AES-256-GCM, under keys kept apart from the replicas. Checking and repairing replicas never needs the keys.
- **Shredding.** Shredding a key makes everything it sealed unreadable on every replica, and in every backup of them. Use it for privacy erasure requests: rotate keys per period or per customer, then shred the one you need to.
- **Fast lookups.** Each replica keeps an index by task, so finding one task's changes doesn't read the whole vault.

Sealed segments can also go to object storage, written once under S3 Object Lock, so for the retention period nobody can delete or change them, whatever their credentials. A bucket in another region is the off-site copy. With an archive configured, segments close after 5 minutes, so the newest archived data is never more than that behind. A lost replica is rebuilt from the archive and then caught up from the others.

```toml
[vault.archive]
endpoint = "https://s3.eu-central-1.amazonaws.com"   # or MinIO, R2, GCS (S3 interface)
region = "eu-central-1"
bucket = "acme-countersign-vault"                    # created with Object Lock enabled
access_key_env = "VAULT_S3_KEY"
secret_key_env = "VAULT_S3_SECRET"
lock_days = 365
```

```sh
undolayer vault check  -c undolayer.toml     # every replica: records, missing, damaged, shared disks
undolayer vault archive -c undolayer.toml    # upload sealed segments now (gateway, serve and worker do it every 30s)
undolayer vault restore-replica /mnt/disk2/countersign -c undolayer.toml
undolayer vault repair -c undolayer.toml
undolayer vault keys | rotate-key | shred-key <id>
```

### See, export, restore and revert what changed

```sh
undolayer changes <tx> --op delete                     # every deleted row or file, with its content
undolayer changes <tx> --format csv --out deleted.csv  # or json, or sql to run by hand
undolayer restore <tx> --key '{"id": 42}' --dry-run    # put chosen rows back...
undolayer restore <tx> --table orders --on-conflict skip
undolayer restore <tx> --path config/app.yaml          # ...or chosen files
undolayer revert --table orders --since 2026-11-27T14:00:00Z  # one table back to a moment
undolayer revert --requester billing-agent --since 2h  # undo everything one caller did
```

`changes` reads the task's journal, or the vault if the journal is gone. Files come back from the vault even when this machine's backup is gone.

A table the task dropped comes back first, with its rows, indexes and triggers. A dropped column comes back with its values, added at the end of the table; `undo` of the whole task restores the exact column order.

`revert --table` restores what every task committed to that table since that moment, newest first, in one new task. Other tables those tasks changed are left as they are.

`restore` puts back only the rows you choose. It first checks that each row is still as that task left it, so a newer change is never overwritten; with `--on-conflict skip` it restores the others and lists the rest. The restore is a new task: it is previewed, approved under your policy, checked again at commit, and can itself be undone. Values come back exactly as they were: integers past 2^53, reals, blobs, NaN, timestamps, arrays, JSON. Parent rows go back before their children.

`revert` undoes a caller's committed tasks newest first. It stops at the first one that can't be undone cleanly, rather than leave an older change undone under a newer one.

### Catch SQL injection by its structure

Injection changes the shape of a query, not only its values. Countersign takes each statement's shape from PostgreSQL's own parser, and from SQLite's tokens plus what SQLite reports about the functions a statement calls and the tables it reads. It reports these signs as facts for policy:

- an always-true `OR` (`OR 1=1`, `OR 'a'='a'`, `OR true`)
- a trailing `--` comment that cuts the query off
- `UNION`
- more than one statement
- reads of system tables
- time delays (`pg_sleep`)
- file, program or code access (`pg_read_file`, `COPY ... PROGRAM`, `dblink`, `load_extension`)

By default, an injected read is refused before it runs; an injected write is staged, measured and sent to a human; time delays and file or program access are refused. Each statement also carries `query_shape`, plus `shape_new` when its caller has never committed a query of that shape (shapes are learned only from committed tasks). Postgres parses each distinct statement once and caches the result.

### Put it in front of PostgreSQL

Applications and agents connect to Countersign as if it were the database. It speaks PostgreSQL's own protocol, including prepared statements, pipelining, COPY and cancel requests.

```toml
[[pg_gateway]]
name = "main"
listen = "127.0.0.1:6432"
primary = "postgres://countersign:...@db-primary:5432/app"   # the gateway's own credentials
replicas = ["postgres://countersign:...@db-replica:5432/app"]
read_only_users = ["reports"]                               # these sessions read from a replica
users = { app = "app-password" }                            # SCRAM-SHA-256; apps never hold the DB password
mode = "enforce"                                            # or "watch": refuse nothing, audit what it would refuse
```

```sh
undolayer pg install -c undolayer.toml    # once per database: row capture and the refusal function
undolayer gateway -c undolayer.toml      # serves every [[pg_gateway]], [[mongo_gateway]] and [[mysql_gateway]]
```

- **Protect.** Each statement is checked from PostgreSQL's own parse tree: injection signs, query shape, and what it touches. The result is cached by statement text. Sessions go to the main database or to a replica that isn't lagging, and the gateway follows a failover. If two servers both claim to be the main database, writes are refused.
- **Block.** A refused statement is answered by the database itself raising the error, so the client sees exactly what any failed statement produces, including an aborted transaction. A transaction is checked again at COMMIT on what it actually changed (rows, share of a table, tables without a primary key), and refused if it went too far.
- **Undo.** Rows are captured as statements run. Before the COMMIT is passed on, every changed row's before state is stored in the vault on a majority of replicas. With no quorum there is no commit. `changes`, `restore`, `revert` and `undo` work on gateway transactions; their ids are in the audit chain as `gateway_commit` events.

Reads pay a cached decision and a relay. Writes pay one extra round trip at COMMIT and a vault write, shared with every other commit in flight.

### Put it in front of MongoDB

The same three steps for MongoDB, at its wire protocol. Drivers connect to Countersign as they would to a `mongos` router.

```toml
[[mongo_gateway]]
name = "docs"
listen = "127.0.0.1:27018"
uri = "mongodb://countersign:...@db1:27017/?authSource=admin"   # the primary or a mongos
users = { app = "app-password" }                                # SCRAM-SHA-256
mode = "enforce"
```

- **Protect.** Each command is checked before it runs. Server-side JavaScript (`$where`, `$function`, `$accumulator`, mapReduce) is how injected input becomes code. Other checks: `$out` and `$merge`, dropping or renaming collections and databases, user and role changes, server administration, and writes to `admin`, `config`, `local` or `system.*`.
- **Block.** A refused command gets an ordinary MongoDB error (code 13, "refused by Countersign: ..."). A write is checked again before it commits, on how many documents it actually changed and what share of the collection that is.
- **Undo.** Every write runs in a transaction.
  - Inside it, the gateway reads the documents the write will change and narrows the write to exactly those `_id`s. It then reads them again afterwards.
  - Both states are stored in the vault as canonical Extended JSON, so every BSON type is kept exactly. This happens before the commit.
  - A client's own transactions are stored when the client commits them.
  - Undo puts each document back in one transaction, and only if it is still as the write left it.

  The server must be a replica set member or a `mongos`. On a standalone server, writes are refused in enforce mode.

### Put it in front of MySQL

Any MySQL driver connects to Countersign as to the server. Both text queries and prepared statements work.

```toml
[[mysql_gateway]]
name = "shop"
listen = "127.0.0.1:3307"
uri = "mysql://countersign:...@db:3306/shop"   # needs TRIGGER and CREATE TEMPORARY TABLES
users = { app = "app-password" }
mode = "enforce"
```

- **Protect.** Each statement is read with MySQL's own lexical rules, including backslash escapes, `#` comments, and the `/*! ... */` comments MySQL runs.
  - Always-true `OR` conditions, `SLEEP` and `BENCHMARK`, file access (`LOAD_FILE`, `INTO OUTFILE`, `LOAD DATA`) and multi-statement queries are refused.
  - So are destroying schema, privilege changes, `PREPARE`/`EXECUTE` in SQL, new routines, server administration, and any attempt to touch capture.
- **Block.** A refused statement gets an ordinary MySQL access-denied error. A transaction is checked again before its COMMIT on what it actually changed: rows, the share of a table, tables without a primary key, and foreign-key cascades.
- **Undo.**
  - The gateway installs triggers on every table and keeps them in step with the schema. They record each changed row, before and after, into a temporary table that only gateway sessions have. Direct sessions skip that branch, so their cost is one `IF`.
  - Before COMMIT is passed on, the rows are checked against the tables' current columns and stored in the vault on a quorum.
  - A write that changed rows nothing recorded is refused. That happens on a table created outside the gateway, until the next sync reaches it (every 10 seconds).
  - Types survive exactly: binary as hex, `TIMESTAMP` as epoch seconds, JSON as JSON.

### Put other MCP servers behind it

```toml
[[mcp_server]]
name = "github"
command = ["npx", "-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_PERSONAL_ACCESS_TOKEN = "..." }   # the agent never sees it
trust_annotations = true                         # run tools marked readOnlyHint at once

[mcp_server.tools.create_issue]
lane = "compensable"
undo = { tool = "update_issue", args = { owner = "$args.owner", repo = "$args.repo", issue_number = "$response.structured.number", state = "closed" } }
```

The server's tools appear as `github_<tool>`. A tool with no declared lane waits for a person and runs on commit; a server's own annotations are only hints. Each tool's definition is pinned the first time Countersign sees it. A tool whose description or schema changes later, or a new tool, is refused until you review it with `undolayer mcp pin github`. URL arguments are checked the same way as HTTP requests. Use `url = "https://..."` (with `headers`) for servers over HTTP.

### Azure and Google Cloud

```toml
[azure]
subscription = "00000000-0000-0000-0000-000000000000"   # tokens from `az account get-access-token`

[gcp.types."compute.googleapis.com/Firewall"]           # tokens from `gcloud auth print-access-token`
collection = "https://compute.googleapis.com/compute/v1/projects/my-project/global/firewalls"
update = "mask"                                         # or "merge" or "put"
```

Resources work as they do on AWS: `azure_resource_update` and `gcp_resource_update` take a JSON Patch, and undo puts back only what the task changed.

- A type becomes undoable after `undolayer azure verify <type> ...` (or `gcp verify`) runs a real create, update, undo and delete with it.
- Azure updates send only what changed, guarded by the resource's etag, so secrets Azure never returns are left alone.
- A create retried after a crash finds the resource it made, and never takes over someone else's.

### HTTP requests and freezing an agent

The agent's own `http.request` calls never reach cloud metadata services (`169.254.169.254`, `metadata.google.internal`, ...). They don't reach private networks either, unless you allow a host in `[http] allow_private_hosts`. This is checked again on the address actually connected to, so DNS rebinding and redirects don't get around it. Other URL schemes, credentials in URLs, and line breaks in headers are refused.

```sh
undolayer freeze billing-agent --reason "unexpected deletes"   # stops it everywhere
undolayer frozen
undolayer unfreeze billing-agent
```

A frozen agent can't run anything or commit anything, on any connector, on any gateway that shares the state store.

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
