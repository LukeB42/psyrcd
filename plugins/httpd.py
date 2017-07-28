import uvloop
import asyncio
from flask import Flask, Response

from tornado.wsgi import WSGIContainer
from tornado.web import Application, FallbackHandler
from tornado.platform.asyncio import AsyncIOMainLoop

ircd = None
app  = Flask("httpd")

def httpd(ctx):
    print(dir())
    return str(dir())

def __init__(ctx):

    @app.route("/")
    def index():
        response = Response(mimetype="text/html")

        response.data = "I have %i clients." % len(ctx.server.clients)

        return response

    container   = WSGIContainer(app)
    application = Application([
        (".*", FallbackHandler, {"fallback": container})    
    ])

    AsyncIOMainLoop().install()
    application.listen(5000)

def __del__(ctx):
    ...

__package__ = {
    "name": "httpd",
    "type": "command",
    "description": "An example HTTPD.",
    "callable": "httpd"
}
