"""
Tests module for EDR Sysmon project.

Provides log replay and testing infrastructure for validating the detection pipeline
on known attack scenarios without requiring live Windows Event Log access.

MODULES:
    - log_replay: Core log replay engine
    - test_runner: Test scenario execution and comparison

QUICK START:
    python -m tests.test_runner attack_scenario
    python -m tests.test_runner --all
    python -m tests.test_runner --compare attack_scenario benign_activity
"""
