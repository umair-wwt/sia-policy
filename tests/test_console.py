from __future__ import annotations

import os

from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document
from prompt_toolkit.history import DummyHistory
from prompt_toolkit.output import ColorDepth

from sia import console


def complete(completer, text):
    return list(completer.get_completions(Document(text), CompleteEvent(completion_requested=True)))


def apply_completion(text, completion):
    return text[:len(text) + completion.start_position] + completion.text


def test_command_completion_replaces_case_and_optional_slash():
    choices = console.ChoiceCompleter({"/settings": "Configure project", "/setup": "First run"}, commands=True)
    for typed in ("/SETT", "sett", "  /sett"):
        found = complete(choices, typed)
        assert len(found) == 1
        assert apply_completion(typed, found[0]) == "/settings"
        assert found[0].display_meta_text == "Configure project"


def test_completion_ranks_prefix_before_substring_and_description():
    choices = console.ChoiceCompleter({"/help": "Find settings help", "/reset": "Start again", "/settings": "Configure"}, commands=True)
    assert [item.text for item in complete(choices, "set")] == ["/settings", "/reset", "/help"]
    assert not complete(choices, "unrecognized")


def test_completion_matches_whole_multiword_value_and_setting_label():
    choices = console.ChoiceCompleter({"/help settings": "Setting reference", "defaults.policy_status": "New policy status"})
    found = complete(choices, "/help se")
    assert apply_completion("/help se", found[0]) == "/help settings"
    assert complete(choices, "new policy")[0].text == "defaults.policy_status"


def test_plain_input_preserves_default_and_monkeypatchability(monkeypatch):
    monkeypatch.setattr(console, "interactive", lambda: False)
    prompts = []
    monkeypatch.setattr("builtins.input", lambda prompt: prompts.append(prompt) or "   ")
    monkeypatch.setattr(console, "PromptSession", lambda **kwargs: (_ for _ in ()).throw(AssertionError("Interactive API used")))
    assert console.read_input("Choose", "yes", choices={"yes": "Continue"}) == "yes"
    assert prompts == ["Choose [yes]: "]


def test_dumb_terminal_disables_interaction_even_with_tty(monkeypatch):
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.setattr(console.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(console.sys.stdout, "isatty", lambda: True)
    assert not console.interactive()


def capture_prompt(monkeypatch, answer=""):
    captured = {}

    class Prompt:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def prompt(self, message, **kwargs):
            captured.update(kwargs)
            captured["message"] = message
            captured["history"].append_string(answer)
            return answer

    monkeypatch.setattr(console, "interactive", lambda: True)
    monkeypatch.setattr(console, "PromptSession", Prompt)
    return captured


def test_live_choices_and_paths_complete_files_with_spaces(tmp_path, monkeypatch):
    (tmp_path / "input data.csv").write_text("header\n", encoding="utf-8")
    captured = capture_prompt(monkeypatch)
    console.read_input("CSV file", choices={"/cancel": "Return without saving"}, path=True)
    found = complete(captured["completer"], str(tmp_path / "input"))
    assert apply_completion(str(tmp_path / "input"), found[0]) == str(tmp_path / "input data.csv")
    assert captured["complete_while_typing"] is True
    assert captured["reserve_space_for_menu"] == 4
    assert complete(captured["completer"], "/can")[0].text == "/cancel"


def test_noncommand_values_have_no_history(monkeypatch):
    captured = capture_prompt(monkeypatch, answer="private setting value")
    console.read_input("Value", choices={"private setting value": "Example"})
    assert isinstance(captured["history"], DummyHistory)
    assert captured["history"].get_strings() == []


def test_command_history_allows_only_known_commands_in_memory(monkeypatch):
    history = console.CommandHistory()
    monkeypatch.setattr(console, "_command_history", history)
    capture_prompt(monkeypatch, answer="/settings")
    console.read_input("sia", choices={"/settings": "Configure"}, commands=True)
    history.append_string("/settings password=accidental-secret")
    history.append_string("accidental-secret")
    assert history.get_strings() == ["/settings"]
    assert not hasattr(history, "filename")


def test_no_color_retains_completion_without_colors(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    captured = capture_prompt(monkeypatch)
    console.read_input("sia", choices={"/help": "Help"}, commands=True)
    assert captured["color_depth"] == ColorDepth.DEPTH_1_BIT
    assert captured["completer"] is not None


def test_plain_presentation_wraps_and_keeps_literal_markup(monkeypatch, capsys):
    monkeypatch.setattr(console, "interactive", lambda: False)
    monkeypatch.setattr(console.shutil, "get_terminal_size", lambda **kwargs: os.terminal_size((36, 24)))
    console.heading("Project home", "A readable guide to configuring your project safely.")
    console.panel("Next step", "Choose [tenant] settings and follow the guided questions.")
    console.menu("Actions", {"/setup": ("Guided setup", "Create the configuration with explanations."), "0": "Exit"})
    console.note("Saved [tenant] configuration.")
    result = capsys.readouterr().out
    assert "[tenant]" in result and "/setup" in result and "\x1b" not in result
    assert all(len(line) <= 36 for line in result.splitlines())


def test_rich_presentation_respects_narrow_width_and_no_color(monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(console, "interactive", lambda: True)
    monkeypatch.setattr(console.shutil, "get_terminal_size", lambda **kwargs: os.terminal_size((40, 24)))
    console.panel("Configuration", "Your [tenant] configuration is saved locally. Run a preview before applying changes.")
    console.menu("Actions", {"/settings": ("Settings", "Configure the tenant and connection options")})
    result = capsys.readouterr().out
    assert "[tenant]" in result and "\x1b" not in result
    assert all(len(line) <= 40 for line in result.splitlines())
