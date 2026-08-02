"""Example plugin — demonstrates optional COMMANDS registration.

Loaded only if shell plugin loader is invoked; does not affect core.
"""


def _hello(args: list[str]) -> None:
    name = args[0] if args else "hunter"
    print(f"[plugin] hello, {name}")


COMMANDS = [
    {
        "name": "hello-plugin",
        "usage": "/hello-plugin [name]",
        "summary": "Example plugin command",
        "handler": _hello,
    }
]
