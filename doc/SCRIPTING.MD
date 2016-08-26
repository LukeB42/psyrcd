
#Scripting

## Design rationale

The ideal scripting API might rely on functions that have specific names. This hasn't been adopted yet in Psyrcd because the current design puts less pressure on memory resources.

It is very likely that this style of scripting will be adopted in future as it will allow run-time metaprogramming at the expense of more __code__ objects.

## How to
| Command       | Help              |
| ------------- |-------------|
| /operserv scripts                   | Lists all loaded scripts. Indicates file modifications if `--debug` isn't being used. |
| /operserv scripts list              | Lists all available scripts.      |
| /operserv load scriptname           | Loads the specified file as a code object using a specific namespace, where a variable called `init` is set to `True`. |
| /operserv scripts unload scriptname | Unloads the specified file by executing its code object with `init` set to `False`. This indicates that file handles in the cache must be closed and structures on affected objects ought to be removed. |

Possible namespaces look like the following:

`namespace = {'client':self,['channel':channel],['mode':mode/'params':params],['setting_mode':bool,'args':args/'display':True],['line':line,'func':func]}`

Modes can be any number of characters long. Modes are entries in a dictionary, called channel.modes and user.mdoes. Mode arguments are stored in lists by default.

The structure on a channel or user object looks like `user.modes['scriptmode']`, where 'scriptmode' points to a list or whatever structure your script manually sets.

The type used to store arguments can be overridden and the way values are appended and removed can be handled from within scripts.

Mode parameters can be stored in Numpy arrays for example. If you have a mode called numpy, you could do something like: `/mode #channel +numpy:123,456,789,0`

`/mode #channel -numpy:` would clear the mode completely, rather than removing individual parameters and then the mode itself.

init and unload ought to cause the script to create or remove structures on channels and clients.

Modes on load are automatically appended to the necessary supported_modes dictionary and removed on unload.

Mode scripts can check for the presence of a variable named `display` in their namespace in order to return custom messages in a variable named `output`.

`@scripts` decorator cycles through modes and match to `server.scripts.umodes.keys()` and `server.scripts.cmodes.keys()`.

Every time a channel name is the target of a command its modes are checked against IRCServer.Scripts.cmodes.

Decorator on `handle_*` will send `self,channel,func,params` into your scripts default namespace.

For example: `/mode #channel +lang:en`

`channel.modes{'l':['50'],'lang':['en'],'n':1,'t':1}`


---

#The Future
`/operserv connect server:port key`; generate key at runtime. This is not implemented yet and would result in a major version increment.

Connect and negotiate as a server, hand connection off to dedicated class.

Most IRCDs keep their modules local and their behaviors are generally not mutually exclusive.

Determine the most elegant way of performing breadth-first search with as little stateful info as possible

decorate `.broadcast()` so it transmits messages across server links. Recipients parse joins/parts/quits

#Known Errors
Windows doesn't have `fork()`. Run in the foreground or Cygwin.

#Todo

Issue a warning and raise SystemExit if psyrcd is already running.

Implement /userhost and /who.

Implement all user and channel modes.

Fix TODO comments.

