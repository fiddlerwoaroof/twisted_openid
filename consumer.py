#!/usr/bin/env python
"""
Simple example for an OpenID consumer.

Once you understand this example you'll know the basics of OpenID
and using the Python OpenID library. You can then move on to more
robust examples, and integrating OpenID into your application.
"""
__copyright__ = 'Copyright 2012, Edward Langley'

import imp, os.path
import cgi
import urlparse
import cgitb
from twisted.web.resource import Resource
import sys

import openid
from openid.consumer import consumer
from openid.oidutil import appendArgs
from openid.extensions import pape, sreg

import mako.template
from openidmongodb import MongoDBStore
from zope.interface import Interface, Attribute, implements
from twisted.python.components import registerAdapter
from twisted.web.server import Session
from twisted.web.resource import Resource
import collections

################### Customization hooks
class EventHandler(object):
	external_port = None
	url = None

	@property
	def store(self):
		self.__class__.store= MongoDBStore()
		return self.store

	def __init__(self, resource):
		self.resource = resource

	@property
	def template(self):
		with file(get_filename('twisted_openid', 'page.mako')) as f:
			return mako.template.Template(f.read())

	def cancel(self, *args, **kwargs):
		pass

	def fail(self, *args, **kwargs):
		pass

	def setup_needed(self, *args, **kwargs):
		pass

	def success(self, *args, **kwargs):
		pass

#################################################

def get_filename(package, resource=None):
   """Get the absolute path to a file inside a given Python package"""
   d = sys.modules[package].__file__
   if resource:
      d = os.path.dirname(d)
      d = os.path.abspath(d)
      return os.path.join(d, resource)
   return d

def quoteattr(s):
	qs = cgi.escape(s, 1)
	return '"%s"' % (qs,)




# Used with an OpenID provider affiliate program.
OPENID_PROVIDER_NAME = 'MyOpenID'
OPENID_PROVIDER_URL ='https://www.myopenid.com/affiliate_signup?affiliate_id=39'



class OpenIDResource(Resource):
	"""Request handler that knows how to verify an OpenID identity."""
	SESSION_COOKIE_NAME = 'pyoidconsexsid'

	eventhandler = EventHandler
	session = None
	isLeaf = True


	def __init__(self, *args, **kw):
		Resource.__init__(self, *args, **kw)
		self.eventhandler = self.eventhandler(self)

	def getConsumer(self, txrequest, stateless=False):
		if stateless:
				store = None
		else:
				store = self.eventhandler.store
		return consumer.Consumer(IOID_Session(txrequest.getSession()), store)


	def render(self, txrequest):
		"""Dispatching logic. There are three paths defined:

			/ - Display an empty form asking for an identity URL to
				verify
			/verify - Handle form submission, initiating OpenID verification
			/process - Handle a redirect from an OpenID server

		Any other path gets a 404 response. This function also parses
		the query parameters.

		If an exception occurs in this function, a traceback is
		written to the requesting browser.
		"""
		o_txrequest_write = txrequest.write
		def txrequest_write(msg, *a, **kw):
			if isinstance(msg, unicode): msg = msg.encode('utf-8')
			return o_txrequest_write(msg, *a, **kw)
		txrequest.write = txrequest_write
		try:
				self.parsed_uri = urlparse.urlparse(txrequest.uri)

				path = '/%s' % '/'.join(txrequest.postpath)
				print path
				if path == '/':
					self.renderPage(txrequest)
				elif path == '/verify':
					self.doVerify(txrequest)
				elif path == '/process':
					self.doProcess(txrequest)
				elif path == '/affiliate':
					self.doAffiliate(txrequest)
				elif path == '/favicon.ico':
					return ''
				else:
					self.notFound(txrequest)

		except (KeyboardInterrupt, SystemExit):
				raise
		except:
				txrequest.setResponseCode(500)
				txrequest.setHeader('Content-type', 'text/html')
				txrequest.getSession()
				return cgitb.html(sys.exc_info(), context=10)
		return ''

	def doVerify(self, txrequest):
		"""Process the form submission, initating OpenID verification.
		"""

		# First, make sure that the user entered something
		openid_url = txrequest.args.get('openid_identifier')
		if not openid_url:
				self.renderPage(txrequest, 'Enter an OpenID Identifier to verify.',
								css_class='error', form_contents=openid_url)
				return
		else:
			openid_url = openid_url[0]

		immediate = 'immediate' in txrequest.args
		use_stateless = 'use_stateless' in txrequest.args

		oidconsumer = self.getConsumer(txrequest, stateless = use_stateless)
		try:
				request = oidconsumer.begin(openid_url)
		except consumer.DiscoveryFailure, exc:
				fetch_error_string = 'Error in discovery: %s' % (cgi.escape(str(exc[0])))
				self.renderPage(txrequest, fetch_error_string, css_class='error', form_contents=openid_url)
		else:
				if request is None:
					msg = 'No OpenID services found for <code>%s</code>' % (
						cgi.escape(openid_url),)
					self.renderPage(txrequest, msg, css_class='error', form_contents=openid_url)
				else:
					trust_root = 'http://%s' % self.eventhandler.url
					if self.eventhandler.external_port and self.eventhandler.external_port != 80:
						trust_root += ':%s' % self.eventhandler.external_port
					return_to = 'http:' + self.buildURL(txrequest, 'process')

					if request.shouldSendRedirect():
						redirect_url = request.redirectURL(trust_root, return_to, immediate=immediate)
						txrequest.redirect(redirect_url)
					else:
						form_html = request.htmlMarkup(
								trust_root, return_to,
								form_tag_attrs={'id':'openid_message'},
								immediate=immediate)

						txrequest.write(form_html)

	def requestRegistrationData(self, request):
		sreg_request = sreg.SRegRequest(
				required=['nickname'], optional=['fullname', 'email'])
		request.addExtension(sreg_request)

	def requestPAPEDetails(self, request):
		pape_request = pape.Request([pape.AUTH_PHISHING_RESISTANT])
		request.addExtension(pape_request)

	def doProcess(self, txrequest):
		"""Handle the redirect from the OpenID server.
		"""
		oidconsumer = self.getConsumer(txrequest)

		# Ask the library to check the response that the server sent
		# us.	Status is a code indicating the response type. info is
		# either None or a string containing more information about
		# the return type.
		url = 'http://'+txrequest.getHeader('Host')+txrequest.path
		query = { k: a[0] if len(a) == 1 else a for k,a in txrequest.args.iteritems() }
		info = oidconsumer.complete(query, url)

		sreg_resp = None
		pape_resp = None
		css_class = 'error'
		display_identifier = info.getDisplayIdentifier()

		message = None
		cb = None
		kwargs = {}
		if info.status == consumer.FAILURE and display_identifier:
			txrequest.getSession().expire()
			cb = self.eventhandler.fail
		elif info.status == consumer.SUCCESS:
			kwargs['canonicalID'] = info.endpoint.canonicalID
			kwargs['display_identifier'] = display_identifier
			kwargs['identity_url'] = info.identity_url
			session = IOID_Session(txrequest.getSession())
			print 'id(session.items)', id(session)
			session.update(kwargs)
			cb = self.eventhandler.success
		elif info.status == consumer.CANCEL:
			txrequest.getSession().expire()
			cb = self.eventhandler.cancel
		elif info.status == consumer.SETUP_NEEDED:
			cb = self.eventhandler.setup_needed
		else:
			txrequest.getSession().expire()
			message = 'Verification failed.'

		if cb is not None:
			cb(txrequest, message, **kwargs)
		else:
			self.renderPage(txrequest, message, display_identifier,
						sreg_data=sreg_resp, pape_data=pape_resp)

#### Untested !!!
#	def doAffiliate(self):
#		"""Direct the user sign up with an affiliate OpenID provider."""
#		sreg_req = sreg.SRegRequest(['nickname'], ['fullname', 'email'])
#		href = sreg_req.toMessage().toURL(OPENID_PROVIDER_URL)
#
#		message = """Get an OpenID at <a href=%s>%s</a>""" % (
#				quoteattr(href), OPENID_PROVIDER_NAME)
#		self.renderPage(txrequest, message)
#
#	def renderSREG(self, sreg_data, txrequest):
#		if not sreg_data:
#				txrequest.write('<div class="alert">No registration data was returned</div>')
#		else:
#				sreg_list = sreg_data.items()
#				sreg_list.sort()
#				txrequest.write(
#					'<h2>Registration Data</h2>'
#					'<table class="sreg">'
#					'<thead><tr><th>Field</th><th>Value</th></tr></thead>'
#					'<tbody>')
#
#				odd = ' class="odd"'
#				for k, v in sreg_list:
#					field_name = sreg.data_fields.get(k, k)
#					value = cgi.escape(v.encode('UTF-8'))
#					txrequest.write(
#						'<tr%s><td>%s</td><td>%s</td></tr>' % (odd, field_name, value))
#					if odd:
#						odd = ''
#					else:
#						odd = ' class="odd"'
#
#				txrequest.write('</tbody></table>')

	def renderPAPE(self, pape_data, txrequest):
		if not pape_data:
				txrequest.write(
					'<div class="alert">No PAPE data was returned</div>')
		else:
				txrequest.write('<div class="alert">Effective Auth Policies<ul>')

				for policy_uri in pape_data.auth_policies:
					txrequest.write('<li><tt>%s</tt></li>' % (cgi.escape(policy_uri),))

				if not pape_data.auth_policies:
					txrequest.write('<li>No policies were applied.</li>')

				txrequest.write('</ul></div>')

	def buildURL(self, txrequest, action='', **query):
		"""Build a URL relative to the server base_url, with the given
		query parameters added."""
		base = '//%s/%s/' % (self.eventhandler.url, '/'.join(txrequest.prepath))
		if not base:
			a  = urlparse.urlparse(txrequest.prePathURL()+'/')

			port = a.port
			if self.eventhandler.external_port:
				port = self.eventhandler.external_port
			if port == 80:
				port = ''
			else:
				port = ':%s' % port

			url = urlparse.SplitResult(
				a.scheme,
				'%s:%s@%s%s' % (
					a.username,
					a.password,
					a.hostname,
					port
				),
				a.path,
				a.query,
				a.fragment)

			base = url.geturl()

		if action:
			base = urlparse.urljoin(base, action)
		print 'buildURL', base
		return appendArgs(base, query)

	def notFound(self):
		"""Render a page with a 404 return code and a message."""
		fmt = 'The path <q>%s</q> was not understood by this server.'
		msg = fmt % (self.path,)
		openid_url = txrequest.args.get('openid_identifier')
		self.renderPage(txrequest, msg, 'error', openid_url, status=404)

	def renderPage(self, txrequest, message=None, css_class='alert', form_contents=None,
					status=200, title="Python OpenID Consumer Example",
					sreg_data=None, pape_data=None):
		"""Render a page."""
		form_contents = form_contents or ''

		txrequest.setResponseCode(status)
		session = txrequest.getSession()
		print 'id(session)', id(session)
		print 'session id:', session.uid
		counter = IOID_Session(session)
		print 'id(session.items)', id(counter)

		result = self.eventhandler.template.render(**dict(
			css_class = css_class,
			action = quoteattr(self.buildURL(txrequest, 'verify')),
			openid = quoteattr(form_contents),
			message = message or 'session details: %s' % counter.items,
		))
		txrequest.write(result);

################################# Twisted Session Management #######################################

class IOID_Session(Interface):
	items = Attribute("An int value which counts up once per page view.")


class OID_Session(collections.MutableMapping):
	implements(IOID_Session)
	def __init__(self, session):
		self.items = {}
	def __len__(self):
		return len(self.items)
	def __iter__(self):
		return iter(self.items)
	def __getitem__(self, name):
		return self.items[name]
	def __setitem__(self, name, value):
		self.items[name] = value
	def __delitem__(self, name):
		del self.items[name]
	def get(self, name, default=None):
		return self.items.get(name, default)


registerAdapter(OID_Session, Session, IOID_Session)

