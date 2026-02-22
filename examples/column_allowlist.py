"""
Column allowlist validation for dynamic SQL in agent data stores.

When an agent builds SQL UPDATE/INSERT statements from keyword arguments
(a common pattern for flexible repository methods), callers could inject
arbitrary column names. A frozenset allowlist validates every kwarg key
before it touches the query string, preventing SQL injection via column names.

This pattern is lightweight — no ORM required, no external dependencies —
and composes well with parameterised queries for values.

Usage:
    from column_allowlist import validate_columns, MessageRepository

    # Low-level: validate a dict before building a query
    updates = {"status": "sent", "sent_at": "2026-02-22T10:00:00"}
    validate_columns(updates, MESSAGES_COLUMNS, "messages")
    # Raises ValueError if any key is not in MESSAGES_COLUMNS

    # High-level: use the repository class which validates internally
    repo = MessageRepository()
    repo.update_message("msg-001", status="sent", sent_at="2026-02-22T10:00:00")

Why frozenset?
    Frozensets are immutable (cannot be modified at runtime) and provide O(1)
    membership tests. Defining them at module level makes the allowlist easy
    to audit via code review.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Column allowlists — one frozenset per logical table / entity.
# Every key that may appear in a dynamic query must be listed here.
# Columns not listed here can never appear in generated SQL, even if an
# attacker controls the kwargs dict.
# ---------------------------------------------------------------------------

# Generic "messages" table: inbound items an agent processes
MESSAGES_COLUMNS = frozenset(
    {
        "id",
        "thread_id",
        "sender_address",
        "sender_name",
        "subject",
        "received_at",
        "processed_at",
        "status",           # pending | processing | done | error
        "action_type",      # read | reply | archive | escalate
        "summary",
        "confidence",
        "is_urgent",
        "tokens_used",
        "processing_ms",
        "model",
    }
)

# Generic "contacts" table: people or organisations the agent knows about
CONTACTS_COLUMNS = frozenset(
    {
        "id",
        "address_pattern",  # email glob or exact address
        "category",
        "display_name",
        "relationship",
        "preferred_tone",   # formal | casual | technical
        "notes",
        "added_at",
        "is_active",
    }
)

# Generic "drafts" table: agent-generated output awaiting human review
DRAFTS_COLUMNS = frozenset(
    {
        "id",
        "message_id",
        "content",
        "edit_distance",    # Levenshtein ratio vs. what was actually sent
        "was_sent",
        "was_discarded",
        "created_at",
        "sent_at",
        "response_category",
    }
)


# ---------------------------------------------------------------------------
# Validation helper
# ---------------------------------------------------------------------------

def validate_columns(kwargs: dict, allowed: frozenset, table: str) -> None:
    """
    Raise ValueError if any key in kwargs is not in the allowed set.

    Call this before building any dynamic SQL clause from a dict of kwargs.
    This is the single enforcement point — all repository methods funnel
    through here so there is no way to skip the check by accident.

    Args:
        kwargs: The dict whose keys will become column names in SQL
        allowed: frozenset of valid column names for this table
        table: Table name, used only in the error message for clarity

    Raises:
        ValueError: Lists every invalid column name found
    """
    invalid = set(kwargs.keys()) - allowed
    if invalid:
        raise ValueError(
            f"Invalid column(s) for table '{table}': {sorted(invalid)}. "
            f"Allowed: {sorted(allowed)}"
        )


# ---------------------------------------------------------------------------
# Example repository — shows how validate_columns fits into a real method.
# In production this would hold a real DB connection; here we use a list
# as a stand-in so the file runs standalone without dependencies.
# ---------------------------------------------------------------------------

class MessageRepository:
    """
    Thin repository for the messages table.

    All mutating methods accept **kwargs for the fields to set. Before
    touching the query, they call validate_columns() to ensure no rogue
    column name can slip through.
    """

    def __init__(self):
        # In production: pass a DB connection or connection factory here.
        # Using a plain list here so the example is fully self-contained.
        self._store: list[dict] = []

    def insert_message(self, **kwargs) -> None:
        """
        Insert a new message record.

        Only fields listed in MESSAGES_COLUMNS are accepted.
        """
        validate_columns(kwargs, MESSAGES_COLUMNS, "messages")

        # Safe to use kwargs now — all keys are in the allowlist.
        # In production you would build a parameterised INSERT here:
        #   cols = ", ".join(kwargs.keys())
        #   placeholders = ", ".join("?" for _ in kwargs)
        #   cursor.execute(f"INSERT INTO messages ({cols}) VALUES ({placeholders})",
        #                  list(kwargs.values()))
        self._store.append(dict(kwargs))
        print(f"[MessageRepository] Inserted: {kwargs}")

    def update_message(self, message_id: str, **kwargs) -> None:
        """
        Update fields on an existing message.

        Only fields listed in MESSAGES_COLUMNS are accepted as kwargs.
        The id field itself is passed positionally to prevent it from
        being accidentally overwritten.
        """
        validate_columns(kwargs, MESSAGES_COLUMNS, "messages")

        # Build a safe SET clause — keys are validated, values are
        # passed via parameterised query (? placeholders), not f-strings.
        # set_clause = ", ".join(f"{k} = ?" for k in kwargs)
        # cursor.execute(f"UPDATE messages SET {set_clause} WHERE id = ?",
        #                [*kwargs.values(), message_id])
        for record in self._store:
            if record.get("id") == message_id:
                record.update(kwargs)
        print(f"[MessageRepository] Updated {message_id}: {kwargs}")


if __name__ == "__main__":
    repo = MessageRepository()

    print("=== Column allowlist demo ===\n")

    # Valid insert
    print("1. Valid insert:")
    repo.insert_message(
        id="msg-001",
        sender_address="sender@example.com",
        subject="Q4 budget review",
        action_type="read",
        confidence=0.92,
    )
    print()

    # Valid update
    print("2. Valid update:")
    repo.update_message("msg-001", status="done", processing_ms=340)
    print()

    # Attempt to inject a rogue column
    print("3. Injection attempt — 'DROP TABLE messages' as column name:")
    try:
        validate_columns(
            {"status": "done", "DROP TABLE messages; --": "malicious"},
            MESSAGES_COLUMNS,
            "messages",
        )
    except ValueError as exc:
        print(f"   Blocked: {exc}")
    print()

    # Attempt via the repository method
    print("4. Injection attempt via repository.update_message:")
    try:
        repo.update_message(
            "msg-001",
            status="sent",
            **{"secret_column; DROP TABLE messages; --": "evil"},
        )
    except ValueError as exc:
        print(f"   Blocked: {exc}")
