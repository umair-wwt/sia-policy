"""Small terminal presentation and completion helpers.

``read_input`` accepts optional ``choices={value: description}``, ``path=True``
for filesystem completion, and ``commands=True`` for allowlisted, memory-only
command history. It never handles secrets. Settings and ordinary prompts have
no history. Redirected input and TERM=dumb use the normal ``input`` function.

``heading``, ``panel``, ``menu`` and ``note`` accept literal text, not markup.
They wrap to the terminal width and remain readable without color.
"""
from __future__ import annotations

import os
import shutil
import sys
import textwrap
from collections.abc import Mapping

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion, PathCompleter, merge_completers
from prompt_toolkit.history import DummyHistory, InMemoryHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def interactive() -> bool:
    """Whether the current streams support interactive terminal controls."""
    return (os.environ.get("TERM", "").lower() != "dumb"
            and bool(getattr(sys.stdin, "isatty", lambda: False)())
            and bool(getattr(sys.stdout, "isatty", lambda: False)()))


class ChoiceCompleter(Completer):
    """Complete whole values; rank prefix matches before text/description matches."""

    def __init__(self, choices: Mapping[str, str], *, commands: bool = False):
        self.choices = {str(key): str(value) for key, value in choices.items()}
        self.commands = commands

    def get_completions(self, document, complete_event):
        entered = document.text_before_cursor
        query = entered.strip().casefold()
        explicit_command = self.commands and query.startswith("/")
        if self.commands:
            query = query.lstrip("/")
        matches = []
        for position, (value, description) in enumerate(self.choices.items()):
            search_value = value.casefold().lstrip("/") if self.commands else value.casefold()
            if search_value.startswith(query):
                rank = 0
            elif query in search_value:
                rank = 1
            elif not explicit_command and query in description.casefold():
                rank = 2
            else:
                continue
            matches.append((rank, position, value, description))
        for _, _, value, description in sorted(matches):
            yield Completion(value, start_position=-len(entered), display_meta=description)


class CommandHistory(InMemoryHistory):
    """Keep only exact known menu commands; never retain arbitrary arguments."""

    def __init__(self):
        super().__init__()
        self.allowed: set[str] = set()

    def append_string(self, string: str) -> None:
        value = string.strip()
        if value.casefold() in self.allowed:
            super().append_string(value)


_command_history = CommandHistory()


def _bindings(has_choices: bool) -> KeyBindings:
    bindings = KeyBindings()
    if not has_choices:
        return bindings

    @bindings.add("tab")
    @bindings.add("down")
    def next_choice(event):
        buffer = event.current_buffer
        if buffer.complete_state:
            buffer.complete_next()
        else:
            buffer.start_completion(select_first=True)

    @bindings.add("s-tab")
    @bindings.add("up")
    def previous_choice(event):
        buffer = event.current_buffer
        if buffer.complete_state:
            buffer.complete_previous()
        else:
            buffer.start_completion(select_last=True)

    return bindings


def read_input(label: str, default: str | None = None, *,
               choices: Mapping[str, str] | None = None, path: bool = False,
               commands: bool = False) -> str:
    """Read a value with live suggestions. Empty input accepts the shown default.

    Tab/Down open and advance suggestions; Up/Shift-Tab select previous choices.
    Ctrl-C and Ctrl-D propagate to the calling screen's cancellation handling.
    Only explicit ``commands=True`` prompts share allowlisted in-memory history.
    """
    suffix = f" [{default}]" if default not in (None, "") else ""
    message = f"{label}{suffix}: "
    if not interactive():
        answer = input(message).strip()
        return answer if answer else (default or "")

    completers: list[Completer] = []
    if choices:
        completers.append(ChoiceCompleter(choices, commands=commands))
    if path:
        completers.append(PathCompleter(expanduser=True))
    completer = merge_completers(completers, deduplicate=True) if completers else None
    history = _command_history if commands else DummyHistory()
    if commands:
        _command_history.allowed = {key.strip().casefold() for key in (choices or {})}
    prompt = PromptSession(history=history)
    no_color = "NO_COLOR" in os.environ
    style = Style.from_dict({
        "prompt": "bold" if no_color else "ansicyan bold",
        "completion-menu.completion.current": "reverse",
        "completion-menu.meta.completion.current": "reverse",
    })
    answer = prompt.prompt(
        [("class:prompt", message)], completer=completer,
        complete_while_typing=True, reserve_space_for_menu=4,
        key_bindings=_bindings(bool(completer)), style=style,
        color_depth=ColorDepth.DEPTH_1_BIT if no_color else None,
    ).strip()
    return answer if answer else (default or "")


_TONES = {"info": "cyan", "success": "green", "warning": "yellow", "error": "red", "muted": "dim"}


def _width() -> int:
    return max(10, min(100, shutil.get_terminal_size(fallback=(80, 24)).columns))


def _output() -> Console:
    return Console(file=sys.stdout, width=_width(), markup=False, highlight=False,
                   no_color="NO_COLOR" in os.environ or not interactive())


def _plain(text: str, *, indent: str = "") -> None:
    for line in str(text).splitlines() or [""]:
        print(textwrap.fill(line, width=_width(), initial_indent=indent,
                            subsequent_indent=indent, replace_whitespace=False) if line else "")


def heading(title: str, subtitle: str = "") -> None:
    print()
    if interactive():
        output = _output()
        output.print(Text(title, style="bold cyan"))
        if subtitle:
            output.print(Text(subtitle, style="dim"))
    else:
        _plain(title)
        _plain("=" * min(len(title), _width()))
        if subtitle:
            _plain(subtitle)


def panel(title: str, body: str, *, tone: str = "info") -> None:
    if interactive():
        _output().print(Panel(Text(str(body)), title=Text(title), title_align="left",
                              border_style=_TONES.get(tone, "cyan"), padding=(0, 1)))
    else:
        print()
        _plain(title)
        _plain(body, indent="  ")


def menu(title: str, items: Mapping[str, tuple[str, str] | str]) -> None:
    """Show a command/number, readable label, and optional concise explanation."""
    if not interactive():
        print()
        _plain(title)
        for key, item in items.items():
            label, description = item if isinstance(item, tuple) else (item, "")
            _plain(f"{key}  {label}", indent="  ")
            if description:
                _plain(description, indent="     ")
        return
    table = Table.grid(padding=(0, 2), expand=True)
    table.add_column(style="cyan", no_wrap=True)
    table.add_column(ratio=1)
    for key, item in items.items():
        label, description = item if isinstance(item, tuple) else (item, "")
        value = Text(label, style="bold")
        if description:
            value.append(f"\n{description}", style="dim")
        table.add_row(Text(key), value)
    _output().print(Panel(table, title=Text(title), title_align="left", border_style="dim"))


def note(message: str, *, tone: str = "muted") -> None:
    if interactive():
        _output().print(Text(str(message), style=_TONES.get(tone, "dim")))
    else:
        _plain(message)
