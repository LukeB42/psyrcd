![Alt text](doc/psyrcd_banner.png?raw=true "Would probably also make for a dope MUD.")

A full IRCD in 60 seconds or triple your money back:
<pre>
git clone https://github.com/LukeB42/psyrcd && cd psyrcd
sudo python setup.py install
psyrcd -f
</pre>
### The Psybernetics IRC Server.

Psyrcd is a pure-python IRCD that supports scriptable commands, user modes and
channel modes, the behavior of which can be redefined while in use.

A NickServ and ChanServ are included as scripts.

**Note:** Psyrcd is noticably faster with [uvloop](https://github.com/MagicStack/uvloop) installed.

![Alt text](doc/psyrcd.png?raw=true "OK now throw NLTK in the mix")

Tested with Python 3.5 on Linux 2.6 to 3.14.
Check the commit history for Python 2.x versions.


