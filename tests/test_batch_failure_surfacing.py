"""Batched trace operations must not fail silently.

ghidratrace's Batch._get_result catches BaseException and *returns* the exception object rather
than raising, so end_batch() hands back a list that may contain exceptions. Every call site here
discarded that list, which meant a failed queued operation -- an endTx among them -- left no
trace in this process and made the next trace operation fail without exposing the original cause.
"""

from unittest.mock import MagicMock

import pytest

from vice import commands


def test_a_clean_batch_raises_nothing():
    client = MagicMock()
    client.end_batch.return_value = ["ok", 1, None]

    commands._end_batch_checked(client, "populate_initial_state")


def test_a_nested_batch_returning_none_is_not_an_error():
    """end_batch() returns None until the refcount reaches zero; only the outermost one waits."""
    client = MagicMock()
    client.end_batch.return_value = None

    commands._end_batch_checked(client, "on_stop")


def test_an_empty_batch_is_not_an_error():
    client = MagicMock()
    client.end_batch.return_value = []

    commands._end_batch_checked(client, "sync_trace")


def test_a_failed_operation_raises_instead_of_being_swallowed():
    client = MagicMock()
    boom = RuntimeError("endTx rejected")
    client.end_batch.return_value = ["ok", boom]

    with pytest.raises(RuntimeError) as caught:
        commands._end_batch_checked(client, "populate_initial_state")

    message = str(caught.value)
    assert "populate_initial_state" in message
    assert "1 of 2" in message
    assert "endTx rejected" in message


def test_the_first_failure_is_reported_and_all_are_counted():
    client = MagicMock()
    client.end_batch.return_value = [
        ValueError("first"),
        "ok",
        RuntimeError("second"),
    ]

    with pytest.raises(RuntimeError) as caught:
        commands._end_batch_checked(client, "on_stop")

    message = str(caught.value)
    assert "2 of 3" in message
    assert "first" in message


def test_the_batch_is_always_ended_even_when_it_failed():
    """end_batch() must be called before the check, or the client is left mid-batch."""
    client = MagicMock()
    client.end_batch.return_value = [RuntimeError("x")]

    with pytest.raises(RuntimeError):
        commands._end_batch_checked(client, "sync_trace")

    client.end_batch.assert_called_once_with()
