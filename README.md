# Psyrcd

A full IRCD in two commands:
<pre>
sudo python setup.py install
psyrcd -f
</pre>
### The Psybernetics IRC Server.

Psyrcd is a pure-python IRCd that supports scriptable commands, user modes and
channel modes, the behavior of which can be redefined while in use.

A NickServ and ChanServ are included as scripts.

![Alt text](doc/psyrcd.png?raw=true "OK now throw NLTK in the mix")

Tested with Python 2.7 on Linux 2.6 to 3.14.

#### Ceaveat lector

Errant scripts can't be removed if they can't be parsed. Scripts tell Psyrcd
what they've added, so we rely on them to determine what to remove.

The best way to avoid this is to specifically check for the types of
invocation a script may concern itself with.
