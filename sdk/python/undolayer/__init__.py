"""undolayer for Python agent applications: put your tools behind the undo layer.

    from undolayer import Undolayer

    ul = Undolayer(approver=lambda req: input(f"approve {req['tool']} {req['args']}? ") == "y")

    @ul.tool(lane="read")
    def get_balance() -> dict: ...

    @ul.tool(lane="irreversible", destinations=["iban"])
    def send_money(iban: str, amount: float) -> dict: ...

    with ul.session("Pay the March invoice") as s:
        s.call("get_balance")
        s.call("send_money", iban="DE89...", amount=98.7)   # waits for the approver
    # commit on exit, rollback on exception

Lanes: read (runs now), deferrable (runs at commit), irreversible (a human approves
first). Everything goes through the real undolayer gateway: policy, approvals, audit log.
"""
from .core import ApprovalRequired, Denied, Session, Undolayer, UndolayerError

__all__ = ["Undolayer", "Session", "UndolayerError", "Denied", "ApprovalRequired"]
__version__ = "0.3.0"
