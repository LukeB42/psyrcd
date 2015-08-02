# news.py for Psyrcd.
# Implements channel mode +news
# Luke Brooks, 2015
# MIT License

# Colour key:
# \x02 bold
# \x03 coloured text
# \x1D italic text
# \x0F colour reset
# \x16 reverse colour
# \x1F underlined text
import datetime as dt
API_KEY = ""
EMISSARY_HOST = "localhost:6362"
EM_IDENT = "Emissary!services@" + cache['config']['SRV_DOMAIN']
COMMAND_PREFIX = ":news"
logging = cache['config']['logging']

def emsg(msg, indent=0):
	if indent:
		client.broadcast(client.nick, ":%s PRIVMSG %s :%s%s" % \
			(EM_IDENT,channel.name," "*indent, msg))
	else:
		client.broadcast(client.nick, ":%s PRIVMSG %s :%s" % \
			(EM_IDENT,channel.name,msg))

def transmit_article_titles(res):
	if res[1] == 200:
		for d in res[0]:
			if not '://' in d['url']:
				d['url'] = "http://" + d['url']
			if d['content_available']:
				emsg("%s: \x037%s\x0F" % (d['feed'],d['title']))
			else:
				emsg("%s: %s" % (d['feed'],d['title']))
			emsg("%s %s \x0314%s\x0F" % \
			(dt.datetime.fromtimestamp(int(d['created'])).strftime('%H:%M:%S %d/%m/%Y'),
			d['uid'], d['url']))
	else:
		emsg("Error.")

def transmit_feed_objects(res):
	(resp, status) = res
	if type(resp) == list:
		for fg in resp:
			transmit_feed_group(fg)
	else:
		transmit_feed_group(resp)

def transmit_feed_group(resp):
	if 'feeds' in resp:
		created = dt.datetime.fromtimestamp(int(resp['created'])).strftime('%H:%M:%S %d/%m/%Y')
		if resp['active'] == True:
			emsg("\x033%s\x0F (created %s)" % (resp['name'], created))
		else:
			emsg("%s (created %s)" % (resp['name'], created))

		for feed in resp['feeds']:
			transmit_feed(feed)
	else:
		transmit_feed(resp)

def transmit_feed(feed):
	created = dt.datetime.fromtimestamp(int(feed['created'])).strftime('%H:%M:%S %d/%m/%Y')
	if feed['active'] == True:
		emsg("\x033%s\x0F" % feed['name'], 2)
	else:
		emsg("%s" % feed['name'], 2)
	emsg("      Created: %s" % created, 2)
	if feed['running'] == True:
		emsg("      Running: \x033%s\x0F" % (feed['running']), 2)
	elif feed['running'] == False:
		emsg("      Running: \x031%s\x0F" % (feed['running']), 2)
	else:
		emsg("      Running: \x0314Unknown\x0F", 2)

	emsg("          URL: %s" % feed['url'], 2)
	emsg("     Schedule: %s" % feed['schedule'], 2)
	emsg("Article count: %s" % "{:,}".format(feed['article_count']), 2)


if 'init' in dir():
	provides = "cmode:news:Provides an in-channel interface to Emissary."
	if init:
		if not API_KEY:
			logging.error("API key undefined in news.py.")
#			client.broadcast("umode:W", ": There's no API key defined in news.py.")
		if not 'client' in cache:
			from emissary.client import Client
			client = Client(API_KEY,'https://%s/v1/' % EMISSARY_HOST, verify=False, timeout=3.5)
			cache['client'] = client
	else:
		if 'client' in cache:
			del cache['client']

if 'display' in dir():
	c = cache['client']
	try:
		output = "({:,} articles)".format(c.get("articles/count")[0])
	except:
		output = "(no connection)"

if 'func' in dir() and func.func_name == "handle_privmsg" and COMMAND_PREFIX in params:
	cancel = True
	params = ' '.join(params.split(':',1)[1:])
	params = params.split()
	if params[0] == COMMAND_PREFIX:

		c = cache['client']

		if params[1].startswith('articles'):
			res = c.get(params[1])
			transmit_article_titles(res)

		elif params[1].startswith('feeds'):
			res = c.get(params[1])
			if res[1] != 200: emsg("Error.")
			if '/search/' in params[1] or '/articles' in params[1]:
				transmit_article_titles(res)
			else:
				transmit_feed_objects(res)

		elif params[1] == 'read':
			(resp, status) = c.get('articles/' + params[2])
			if status != 200:
				emsg("Error status %i" % status)
			else:
				if not resp['content']:
					emsg("No content.")
				else:
					title = resp['title']
					url = resp['url']
					created = resp['created']
					content = resp['content']
					emsg(title)
					emsg(url)
					emsg("")
					for line in content.split('\n'):
						emsg(line)

	del c

del API_KEY
