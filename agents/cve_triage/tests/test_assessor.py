"""Both providers build the same structured-output chain; no network calls."""

import pytest

from cve_triage.assess import LLMAssessor


@pytest.mark.parametrize("provider,model,expected", [
    ("anthropic", None, "anthropic:claude-haiku-5-5"),
    ("openai", None, "openai:gpt-6-luna"),
    ("openai", "gpt-5.6-luna", "openai:gpt-5.6-luna"),
])
def test_providers(monkeypatch, provider, model, expected):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    a = LLMAssessor(provider, model)
    assert a.model == expected and a([]) == []


def test_openai_reasoning_effort(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    assert LLMAssessor("openai").llm.reasoning_effort == "low"
    assert LLMAssessor("openai", reasoning_effort="medium").llm.reasoning_effort == "medium"


def test_unknown_provider():
    with pytest.raises(ValueError, match="unknown provider"):
        LLMAssessor("mistral")
