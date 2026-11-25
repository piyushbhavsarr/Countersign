# undolayer for Python agent apps

Put your agent's existing tools behind the undo layer in a few lines. Every call goes through the undolayer gateway: policy, approvals, audit log. Nothing happens to the world until you commit, and you can still undo afterwards.

```python
from undolayer import Undolayer

ul = Undolayer(approver=my_review)          # my_review(request) -> True/False, called live

@ul.tool(lane="read")
def search_orders(customer: str) -> list: ...

@ul.tool(lane="deferrable", destinations=["to"])          # sent at commit
def send_email(to: str, subject: str, body: str) -> dict: ...

@ul.tool(lane="irreversible", destinations=["iban"])      # a human approves first
def refund(iban: str, amount: float) -> dict: ...

with ul.session(user_request) as s:          # the user's request: destinations it doesn't name need approval
    messages += s.handle(llm_response.tool_calls)   # OpenAI-style function calling
    # or: s.call("refund", iban=..., amount=...)    # direct
    # or: s.langchain_tools()                        # LangChain
# commit on exit; any exception rolls everything back
```

* **Lanes:**
  * `read` runs now;
  * `deferrable` takes effect at commit;
  * `irreversible` waits for a human.
* **`destinations`** names the arguments that say where an effect goes: recipients, an account, a URL. If one of them isn't in the user's request (for example, the agent read it from an email), it needs approval. This is what stops prompt-injected "send it to the attacker" actions.
* **Approvals:**
  * `approver=` answers each request while the agent waits.
  * Without an approver, requests wait for `undolayer approve` at commit.
  * From a terminal: `undolayer pending`, then `undolayer approve <tx> --action <id> [--decline]`.
* **Existing config:** `Undolayer(config="undolayer.toml")` adds your tools to an existing gateway config (workspace, SQL, credentials, policy).

The SDK needs the `undolayer` binary on `PATH`, or `UNDOLAYER_BIN` set.
