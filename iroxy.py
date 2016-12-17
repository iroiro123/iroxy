#
# for mitmproxy 0.18.1 ( 0.18.2 is buggy )
# Usage: mitmproxy -s iroxy.py -p 8000
#        mitmproxy -s iroxy.py -R http://upstream:8001 -p 8000
#

import re
from mitmproxy import ctx
from mitmproxy.models.connections import ServerConnection,ClientConnection
from mitmproxy.protocol import Layer,ServerConnectionMixin
from mitmproxy.protocol.tls import TlsLayer,TlsClientHello
from mitmproxy import exceptions

class MyTlsLayer(TlsLayer):
	def __call__(self):
		try:
			self._client_hello = TlsClientHello.from_client_conn(self.client_conn)
		except exceptions.TlsProtocolException as e:
			self.log("Cannot parse Client Hello: %s" % repr(e), "error")
		
		sni = None
		if self._client_hello:
			sni = self._client_hello.sni
		
		if sni:
			self.set_server((sni,443))
			self._establish_tls_with_client_and_server()
		elif self._client_tls:
			self._establish_tls_with_client()
		
		layer = self.ctx.next_layer(self)
		layer()

class MyReverseProxy(Layer, ServerConnectionMixin):
	def __call__(self):
		layer = self.ctx.next_layer(self) # TlsLayer
		try:
			layer.__class__ = MyTlsLayer
			layer()
		finally:
			if self.server_conn:
				self.disconnect()

def start():
	ctx.master.options.mode = MyReverseProxy

def requestheaders(flow):
	if flow.server_conn:
		return
	
	if flow.client_conn.ssl_established:
		scheme = "https"
	else:
		scheme = "http"
	
	# get host from host header
	host,port = flow.request._parse_host_header()
	
	# unknown host, redirect to local
	if not host:
		if ctx.master.server.config.upstream_server:
			host = ctx.master.server.config.upstream_server.address.host
			port = ctx.master.server.config.upstream_server.address.port
			scheme = ctx.master.server.config.upstream_server.scheme
		else:
			host = "127.0.0.1"
			port = 8001
			scheme = "http"
	
	# implicit port
	if not port:
		if scheme == "https":
			port = 443
		else:
			port = 80
	
	addr = (host,port)
	
	# connect to server
	flow.server_conn.address = addr
	flow.server_conn.connect()
	
	# untrusted connection because of no certification
	if scheme == "https" and not flow.server_conn.tls_established:
		flow.server_conn.establish_ssl(None, host)
	
	flow.request.host = host
	flow.request.port = port
	flow.request.scheme = scheme
