#!/usr/bin/env python
import logging

from codereview import views

from google.appengine.ext import webapp
from google.appengine.ext.webapp.mail_handlers import InboundMailHandler
from google.appengine.ext.webapp.util import run_wsgi_app
class MailHandler(InboundMailHandler):
  def receive(self, message):
    views.updatefromemail(message)
    pass

application = webapp.WSGIApplication([
  MailHandler.mapping()
], debug=True)

def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()