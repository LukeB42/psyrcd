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

API_KEY = ""
EM_IDENT = "EmissaryServ!services@" + cache['config']['SRV_DOMAIN']

def emsg(msg):
	client.broadcast(client.nick, ":%s PRIVMSG %s :%s" % \
		(EM_IDENT,channel.name,msg))

if 'init' in dir():
	provides = "cmode:news:Provides an in-channel interface to Emissary."
	if init:
		if not 'client' in cache:
			from emissary.client import Client
			client = Client(API_KEY,'https://localhost:6362/v1/', verify=False)
			cache['client'] = client
	else:
		del cache['client']

if 'display' in dir():
	c = cache['client']
	output = "({:,} articles)".format(c.get("articles/count")[0])

if 'func' in dir():
	cancel = True
	params = ' '.join(params.split(':',1)[1:])
	params = params.split()
	if params[0] == ':news':

		c = cache['client']

		if params[1].startswith('articles'):
			res = c.get(params[1])
			if res[1] == 200:
				for d in res[0]:
					if not '://' in d['url']:
						d['url'] = "http://" + d['url']
					if d['content_available']:
						emsg("%s: \x033%s\x0F" % (d['feed'],d['title']))
					else:
						emsg("%s: %s" % (d['feed'],d['title']))
					emsg("%s \x0314%s\x0F" % (d['uid'], d['url']))
			else:
				emsg("Error.")

		elif params[1] == 'read':
			res = c.get('articles/' + params[2])
			if res[1] == 200:
				if not res[0]['content']: emsg("No content.")
				else:
					title = res[0]['title']
					url = res[0]['url']
					created = res[0]['created']
					content = res[0]['content']
					for line in content.split('\n'):
						emsg(line)

			else:
				emsg("Error.")

		elif params[1].startswith('feeds'):
			res = c.get(params[1])
			if res[1] != 200: emsg("Error.")
			else:
				import pprint
				for line in pprint.pformat(res[0]).split('\n'):
					emsg(line)
	del c
