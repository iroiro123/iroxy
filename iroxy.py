#
# Iroxy - semi-transparent proxy
#   inline script for mitmproxy 0.18.1 ( 0.18.2 is buggy )
#
# Usage:
#   mitmproxy [-p <listen port>] -s 'iroxy.py [spoofed https port]' [-R <fallback server>]
#   mitmproxy -p 8000 -s iroxy.py
#   mitmproxy -p 8000 -s iroxy.py -R http://127.0.0.1:8001
#   mitmproxy -p 8000 -s 'iroxy.py 443'
#
# Released under the MIT license.
# (c) 2016 iroiro123
#

import sys
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy.protocol import Layer,ServerConnectionMixin
from mitmproxy.protocol.tls import TlsLayer,TlsClientHello

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
			global upstream_tlsport
			self.set_server((sni,upstream_tlsport))
			self._establish_tls_with_client_and_server()
		elif self._client_tls:
			self._establish_tls_with_client()
		
		layer = self.ctx.next_layer(self)
		layer()

class MyReverseProxy(Layer, ServerConnectionMixin):
	def __call__(self):
		layer = self.ctx.next_layer(self) # TlsLayer
		try:
			layer()
		finally:
			if self.server_conn:
				self.disconnect()

def next_layer(layer):
	if isinstance(layer, TlsLayer) and isinstance(layer.ctx, MyReverseProxy):
		layer.__class__ = MyTlsLayer

def start():
	start_with_args(*sys.argv[1:])

def start_with_args(tlsport="443", *argv):
	ctx.master.options.mode = MyReverseProxy
	
	global upstream_tlsport
	upstream_tlsport = int(tlsport)

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
	
	flow.request.host = host
	flow.request.port = port
	flow.request.scheme = scheme
	
	# connect to server
	flow.server_conn.address = addr
	try:
		flow.server_conn.connect()
	except:
		return
	
	# untrusted connection because of no certification
	if scheme == "https" and not flow.server_conn.tls_established:
		flow.server_conn.establish_ssl(None, host)
