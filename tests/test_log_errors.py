"""
Tests for the log_errors decorator in hooks.py.

Validates that event handler exceptions are caught, logged, and not propagated.
"""

import logging

import pytest

from vice.hooks import log_errors


class TestLogErrors:
    def test_normal_function_returns_value(self):
        @log_errors
        def good():
            return 42
        assert good() == 42

    def test_exception_is_swallowed(self):
        @log_errors
        def bad():
            raise RuntimeError("boom")
        # Must not raise
        result = bad()
        assert result is None

    def test_exception_is_logged(self, caplog):
        @log_errors
        def bad():
            raise ValueError("test error")
        with caplog.at_level(logging.ERROR):
            bad()
        assert "test error" in caplog.text
        assert "bad" in caplog.text

    def test_preserves_function_name(self):
        @log_errors
        def my_handler():
            pass
        assert my_handler.__name__ == 'my_handler'

    def test_passes_args_through(self):
        @log_errors
        def add(a, b):
            return a + b
        assert add(3, 4) == 7

    def test_passes_kwargs_through(self):
        @log_errors
        def greet(name='world'):
            return f'hello {name}'
        assert greet(name='test') == 'hello test'

    def test_keyboard_interrupt_not_swallowed(self):
        """KeyboardInterrupt and SystemExit should NOT be caught."""
        @log_errors
        def interrupt():
            raise KeyboardInterrupt()
        with pytest.raises(KeyboardInterrupt):
            interrupt()

    def test_system_exit_not_swallowed(self):
        @log_errors
        def exit_now():
            raise SystemExit(1)
        with pytest.raises(SystemExit):
            exit_now()
