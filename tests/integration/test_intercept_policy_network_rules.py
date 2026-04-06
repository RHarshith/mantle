"""Integration checks for intercept network policy ordering/patterns."""

from pathlib import Path

import pytest


@pytest.mark.integration
def test_network_policy_has_specific_rules_before_catch_all():
    policy_text = Path(".mantle/intercept.yaml").read_text(encoding="utf-8")

    star_idx = policy_text.find('- destination: "*"')
    github_idx = policy_text.find('- destination: "*github.com*"')
    github_ip_idx = policy_text.find('- destination: "140.82.*:443"')

    assert github_idx != -1, "Expected github wildcard rule in network policy"
    assert github_ip_idx != -1, "Expected GitHub IP-range fallback rule in network policy"
    assert star_idx != -1, "Expected catch-all destination rule in network policy"
    assert github_idx < star_idx, "GitHub hostname rule must appear before catch-all"
    assert github_ip_idx < star_idx, "GitHub IP rule must appear before catch-all"
