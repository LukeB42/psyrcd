import uvloop
import asyncio
from flask import Flask, Response

from tornado.wsgi import WSGIContainer
from tornado.web import Application, FallbackHandler
from tornado.platform.asyncio import AsyncIOMainLoop

ircd = None

app  = Flask("httpd")
@app.route("/")
def index():
    global ircd
    response = Response(mimetype="text/html")
    response.data = "I have %i clients." % len(ircd.clients)

    return response

def httpd(ctx):
    return "Running."

def __init__(ctx):
    global ircd
    ircd = ctx.server
    container   = WSGIContainer(app)
    application = Application([
        (".*", FallbackHandler, {"fallback": container})    
    ])

    AsyncIOMainLoop().install()
    try:
        application.listen(5000)
    except OSError as err:
        raise RuntimeError("httpd: could not bind port 5000: %s" % err)

def __del__(ctx):
    ...

__package__ = {
    "name": "httpd",
    "type": "command",
    "description": "An example HTTPD.",
    "callable": "httpd"
}
