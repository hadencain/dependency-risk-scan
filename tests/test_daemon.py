# tests/test_daemon.py
import pytest
from deprisk.daemon import run_loop


def test_run_loop_runs_n_iterations():
    calls = []
    run_loop(lambda: calls.append(1) or 0, interval=0, iterations=3,
             sleep=lambda _: None)
    assert len(calls) == 3


def test_run_loop_returns_last_nonzero_code():
    codes = iter([0, 1, 0])
    rc = run_loop(lambda: next(codes), interval=0, iterations=3,
                  sleep=lambda _: None)
    assert rc == 1


def test_run_loop_survives_tick_exception(capsys):
    state = {"n": 0}

    def tick():
        state["n"] += 1
        if state["n"] == 2:
            raise RuntimeError("boom")
        return 0

    rc = run_loop(tick, interval=0, iterations=3, sleep=lambda _: None)
    assert state["n"] == 3
    assert rc == 0
    assert "boom" in capsys.readouterr().err
