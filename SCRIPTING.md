# Writing Plugins for psyrcd

Plugins are plain Python modules dropped into `plugins/`. The server loads them
at startup with `--preload`, or on demand via `/operserv plugins load <name>`.
They run inside the server process with full access to every live object on the
network — channels, clients, modes, the event loop, all of it.

## Anatomy of a plugin

Every plugin needs three things:

```python
# 1. Declare what you're providing
__package__ = [
    {"name": "hello", "type": "command", "description": "Greets the user."},
]

# 2. Your handler
def hello(ctx):
    return ":%s NOTICE %s :Hello, %s!" % (
        ctx.client.server.servername,
        ctx.client.nick,
        ctx.client.nick,
    )

# 3. Lifecycle hooks
def __init__(ctx):
    __package__[0]["callable"] = hello   # wire up the handler

def __del__(ctx):
    pass                                 # clean up anything you allocated
```

Drop it in `plugins/` and you're done. `/hello` now works on the server.

## Plugin types

| `type`    | Triggered by                               | Example use                   |
|-----------|--------------------------------------------|-------------------------------|
| `command` | A client sending that IRC command          | `/nickserv`, `/disect`, `/ns` |
| `umode`   | Any command from a user who has that mode  | Mode `R` — registered nick    |
| `cmode`   | Any command issued inside that channel     | Mode `G` — phrase substitution|

A single file can register multiple entries — NickServ registers `nickserv`,
`ns`, umode `R`, and cmode `c` all at once.

## The context object (`ctx`)

Your handler receives a `ScriptContext` dict with attribute access:

| Attribute        | What it is                                           |
|------------------|------------------------------------------------------|
| `ctx.client`     | The `IRCClient` who sent the command                 |
| `ctx.line`       | A `Line` object; `.body` is the full command string  |
| `ctx.channel`    | The `IRCChannel` (cmode handlers only)               |
| `ctx.mode`       | The mode letter that triggered this handler          |
| `ctx.func`       | The built-in handler being wrapped (umode/cmode)     |
| `ctx.cancel`     | Set to `True` to suppress the built-in handler       |
| `ctx.params`     | Modify this to rewrite the params before the built-in runs |

From `ctx.client` you can reach everything:

```python
client  = ctx.client
server  = client.server
channel = server.channels.get("#general")
user    = server.clients.get("Alice")
```

## Returning a response

Command plugins return a raw IRC protocol string, which gets sent to the client:

```python
def hello(ctx):
    return ":%s NOTICE %s :Hello!" % (
        ctx.client.server.servername,
        ctx.client.nick,
    )
```

Return an empty string (or `None`) to send nothing.

To send multiple lines, call `ctx.client.broadcast()` directly and return `""`:

```python
def hello(ctx):
    for line in ["one", "two", "three"]:
        ctx.client.broadcast(ctx.client.nick, ": %s" % line)
    return ""
```

## Intercepting commands with cmode/umode plugins

A cmode plugin fires **instead of** (or **before**) the built-in handler for
every command a user sends inside a mode-enabled channel. Use `ctx.func` to
see which handler is being called, and `ctx.cancel = True` to block it:

```python
# replace.py — rewrites PRIVMSG text in channels with mode +G
def G(ctx):
    if ctx.get('func') and ctx.func.__name__ == "handle_privmsg":
        params = ctx.get('params', '')
        # ... rewrite ctx["params"] ...
```

Setting `ctx["params"]` passes modified params to the built-in handler.

## Module-level state

Need to keep state across calls? Use module-level variables, initialised in
`__init__`. This is the pattern used by NickServ, ChanServ, and news:

```python
_db = None

def __init__(ctx):
    global _db
    __package__[0]["callable"] = my_handler
    _db = open_database()

def __del__(ctx):
    global _db
    if _db:
        _db.close()
        _db = None
```

`ctx` in `__init__` has `ctx.server` — use it to grab the server domain,
config values, or anything else you need at load time.

## Live development with `--debug`

Start the server with `--debug` and every command plugin is reloaded from disk
on every single invocation:

```
python psyrcd.py --preload --debug
```

That means the edit-test loop is just:

1. Edit `plugins/myplugin.py`
2. `/myplugin` in your IRC client
3. See the result immediately — no reload command needed

`--debug` also enables asyncio's own debug mode (extra coroutine warnings) and
promotes `logging.debug` messages to `INFO` level so they appear in the
console.

Note: the `*` modified-file marker in `/operserv plugins` is suppressed in
debug mode because files are always fresh.

## Managing plugins at runtime

```
/operserv plugins           — list loaded plugins and their hashes
/operserv plugins list      — list all available plugins and load state
/operserv plugins load foo  — load plugins/foo.py
/operserv plugins unload foo
```

Files marked with `*` next to their name have changed on disk since they were
loaded — reload them to pick up edits (or just use `--debug` during
development).

## Real examples in this repo

| File              | What it does                                          |
|-------------------|-------------------------------------------------------|
| `foo.py`          | Minimal skeleton — start here                         |
| `disect.py`       | IRCop command: inspect live channel/user objects      |
| `replace.py`      | cmode `+G`: phrase substitution in PRIVMSG            |
| `sortition.py`    | cmode `+sortition`: random op rotation on a timer     |
| `capabilities.py` | Overrides the built-in CAP handler for IRCv3          |
| `NickServ.py`     | Full service: command + umode + cmode, SQLite backend |
| `ChanServ.py`     | Channel registration service                          |
| `news.py`         | `/news` command backed by an external API client      |
