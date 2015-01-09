#!/usr/bin/env python
# coding:utf-8

"""A simple python clone for stunnel+squid"""

__version__ = '1.0.0'

import os
import sys
import sysconfig

reload(sys).setdefaultencoding('UTF-8')
sys.dont_write_bytecode = True
sys.path = [(os.path.dirname(__file__) or '.') + '/packages.egg/noarch'] + sys.path + [(os.path.dirname(__file__) or '.') + '/packages.egg/' + sysconfig.get_platform().split('-')[0]]

try:
    __import__('gevent.monkey', fromlist=['.']).patch_all()
except (ImportError, SystemError):
    sys.exit(sys.stderr.write('please install python-gevent\n'))

import logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')

import base64
import time
import BaseHTTPServer
import hmac

from proxylib import BaseFetchPlugin
from proxylib import BaseProxyHandlerFilter
from proxylib import SimpleProxyHandler
from proxylib import LocalProxyServer
from proxylib import AdvancedNet2
from proxylib import random_hostname
from proxylib import forward_socket
from proxylib import CertUtility
from proxylib import RC4Socket


class VPSFetchPlugin(BaseFetchPlugin):
    """vps fetch plugin"""

    def __init__(self):
        BaseFetchPlugin.__init__(self)

    def handle(self, handler, **kwargs):
        logging.info('%s "%s %s %s" - -', handler.address_string(), handler.command, handler.path, handler.protocol_version)
        if handler.command != 'CONNECT':
            handler.wfile.write('HTTP/1.1 403 Forbidon\r\n\r\n')
            return
        cache_key = kwargs.pop('cache_key', '')
        sock = handler.net2.create_tcp_connection(handler.host, handler.port, handler.net2.connect_timeout, cache_key=cache_key)
        handler.connection.send('HTTP/1.1 200 OK\r\n\r\n')
        forward_socket(handler.connection, sock, 60, 256*1024)


class VPSProxyFilter(BaseProxyHandlerFilter):
    """vps filter"""
    def __init__(self):
        BaseProxyHandlerFilter.__init__(self)

    def filter(self, handler):
        cache_key = '%s:%d' % (handler.host, handler.port)
        if handler.command == 'CONNECT':
            return 'vps', {'cache_key': cache_key}
        else:
            return 'direct', {'cache_key': cache_key}


class VPSProxyHandler(SimpleProxyHandler):
    """GAE Proxy Handler"""
    handler_filters = [VPSProxyFilter()]

    def setup(self):
        self.__class__.do_CONNECT = self.__class__.do_METHOD
        self.__class__.do_GET = self.__class__.do_METHOD
        self.__class__.do_PUT = self.__class__.do_METHOD
        self.__class__.do_POST = self.__class__.do_METHOD
        self.__class__.do_HEAD = self.__class__.do_METHOD
        self.__class__.do_DELETE = self.__class__.do_METHOD
        self.__class__.do_OPTIONS = self.__class__.do_METHOD
        self.__class__.do_PATCH = self.__class__.do_METHOD
        key = '123456'
        seed = self.request.recv(4)
        logging.info('current seed %r', seed)
        self.request = RC4Socket(self.request, hmac.new(key, seed).digest())
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)


def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x: x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    VPSProxyHandler.handler_plugins['vps'] = VPSFetchPlugin()
    VPSProxyHandler.net2 = AdvancedNet2(window=2, ssl_version='SSLv23')
    VPSProxyHandler.net2.enable_connection_cache()
    VPSProxyHandler.net2.enable_connection_keepalive()
    server = LocalProxyServer(('', 443), VPSProxyHandler)
    server.serve_forever()

if __name__ == '__main__':
    main()
