from unittest.mock import MagicMock

import pytest

from vice import commands, hooks


@pytest.fixture(autouse=True)
def reset_state():
    commands.STATE.controller = None
    yield
    commands.STATE.controller = None


def test_install_hooks_requires_controller():
    with pytest.raises(RuntimeError, match="Not connected"):
        hooks.install_hooks()


def test_install_hooks_accepts_shared_client_identity():
    client = MagicMock()
    controller = MagicMock(client=client)
    commands.STATE.controller = controller
    hooks.install_hooks()


def test_install_hooks_rejects_identity_mismatch(monkeypatch):
    commands.STATE.controller = MagicMock(client=MagicMock())
    monkeypatch.setattr(
        commands.STATE, "require_vice", lambda: MagicMock()
    )
    with pytest.raises(RuntimeError, match="identity mismatch"):
        hooks.install_hooks()
