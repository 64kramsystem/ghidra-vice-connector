from unittest.mock import MagicMock, patch

import pytest

from vice import commands
from vice.controller import ViceController
from vice.protocol import ViceBmpClient


@pytest.fixture(autouse=True)
def reset_state():
    commands.STATE.controller = None
    commands.STATE.client = None
    commands.STATE.trace = None
    yield
    if commands.STATE.controller is not None:
        commands.STATE.controller.close()
    commands.STATE.controller = None
    commands.STATE.client = None
    commands.STATE.trace = None


def test_connect_vice_creates_exactly_one_client_and_controller(mock_server):
    commands.connect_vice("127.0.0.1", mock_server.port)
    assert isinstance(commands.STATE.controller, ViceController)
    assert isinstance(commands.STATE.require_vice(), ViceBmpClient)
    assert commands.STATE.controller.client is commands.STATE.require_vice()
    assert commands.STATE.controller.vice_version == "3.10.0.0"


def test_connect_vice_does_not_start_second_socket(mock_server):
    commands.connect_vice("127.0.0.1", mock_server.port)
    first = commands.STATE.require_vice()
    assert commands.STATE.controller.client is first
    assert first.ping()


def test_start_trace_creates_trace_without_automatic_save():
    fake_socket = MagicMock()
    fake_client = MagicMock()
    fake_trace = MagicMock()
    fake_client.create_trace.return_value = fake_trace
    with patch("vice.commands.socket.socket", return_value=fake_socket), patch(
        "vice.commands.Client", return_value=fake_client
    ):
        commands.start_trace("127.0.0.1", 1234, MagicMock())
    fake_socket.connect.assert_called_once_with(("127.0.0.1", 1234))
    fake_client.create_trace.assert_called_once()
    fake_trace.save.assert_not_called()
