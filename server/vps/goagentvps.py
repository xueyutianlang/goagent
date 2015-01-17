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

import socket
import errno
import ssl
import select
import hmac
import struct
import zlib

import gevent
import gevent.server


try:
    from Crypto.Cipher.ARC4 import new as RC4Cipher
except ImportError:
    logging.warn('Load Crypto.Cipher.ARC4 Failed, Use Pure Python Instead.')
    class RC4Cipher(object):
        def __init__(self, key):
            x = 0
            box = range(256)
            for i, y in enumerate(box):
                x = (x + y + ord(key[i % len(key)])) & 0xff
                box[i], box[x] = box[x], y
            self.__box = box
            self.__x = 0
            self.__y = 0
        def encrypt(self, data):
            out = []
            out_append = out.append
            x = self.__x
            y = self.__y
            box = self.__box
            for char in data:
                x = (x + 1) & 0xff
                y = (y + box[x]) & 0xff
                box[x], box[y] = box[y], box[x]
                out_append(chr(ord(char) ^ box[(box[x] + box[y]) & 0xff]))
            self.__x = x
            self.__y = y
            return ''.join(out)


class CipherFileObject(object):
    """fileobj wrapper for cipher"""
    def __init__(self, fileobj, cipher, mode='r'):
        self.__fileobj = fileobj
        self.__cipher = cipher
        if 'r' not in mode:
            self.read = self.__fileobj.read
        if 'w' not in mode:
            self.write = self.__fileobj.write

    def __getattr__(self, attr):
        if attr not in ('__fileobj', '__cipher'):
            return getattr(self.__fileobj, attr)

    def read(self, size=-1):
        return self.__cipher.encrypt(self.__fileobj.read(size))

    def write(self, data):
        return self.__fileobj.write(self.__cipher.encrypt(data))


class RC4Socket(object):
    """socket wrapper for cipher"""
    def __init__(self, sock, key):
        self.__sock = sock
        self.__key = key
        self.__recv_cipher = RC4Cipher(key)
        self.__send_cipher = RC4Cipher(key)

    def __getattr__(self, attr):
        print (self, attr)
        if attr not in ('__sock', '__cipher'):
            return getattr(self.__sock, attr)

    def recv(self, size):
        data = self.__sock.recv(size)
        return data and self.__recv_cipher.encrypt(data)

    def send(self, data, flags=0):
        return data and self.__sock.send(self.__send_cipher.encrypt(data), flags)

    sendall = send

    def dup(self):
        return RC4Socket(self.__sock.dup(), self.__key)

    def makefile(self, mode, bufsize):
        cipher = None
        if 'r' in mode:
            cipher = self.__recv_cipher
        if 'w' in mode:
            cipher = self.__send_cipher
        return CipherFileObject(self.__sock.makefile(mode, bufsize), cipher, mode)


def inflate(data):
    return zlib.decompress(data, -zlib.MAX_WBITS)


def deflate(data):
    return zlib.compress(data)[2:-4]


def forward_socket(local, remote, timeout, bufsize):
    """forward socket"""
    try:
        tick = 1
        timecount = timeout
        while 1:
            timecount -= tick
            if timecount <= 0:
                break
            (ins, _, errors) = select.select([local, remote], [], [local, remote], tick)
            if errors:
                break
            for sock in ins:
                data = sock.recv(bufsize)
                if not data:
                    break
                if sock is remote:
                    local.sendall(data)
                    timecount = timeout
                else:
                    remote.sendall(data)
                    timecount = timeout
    except socket.timeout:
        pass
    except (socket.error, ssl.SSLError) as e:
        if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
            raise
        if e.args[0] in (errno.EBADF,):
            return
    finally:
        for sock in (remote, local):
            try:
                sock.close()
            except StandardError:
                pass


class TCPServer(gevent.server.StreamServer):
    """VPS tcp server"""
    def __init__(self, *args, **kwargs):
        self.password = kwargs.pop('password')
        gevent.server.StreamServer.__init__(self, *args, **kwargs)

    def readn(self, sock, n):
        buf = ''
        while n > 0:
            data = sock.recv(n)
            if not data:
                raise socket.error(errno.EPIPE, 'Unexpected EOF')
            n -= len(data)
            buf += data
        return buf

    def handle(self, sock, address):
        seed = self.readn(sock, 4)
        digest = hmac.new(self.password, seed).digest()
        csock = RC4Socket(sock, digest)
        domain = self.readn(csock, ord(self.readn(csock, 1)))
        port, = struct.unpack('>H', self.readn(csock, 2))
        flag = ord(self.readn(csock, 1))
        data = ''
        do_ssl_handshake = False
        if flag & 0x1:
            raise ValueError('Now UDP is unsupported')
        if flag & 0x2:
            do_ssl_handshake = True
        if flag & 0x4:
            datasize, = struct.unpack('>H', self.readn(csock, 2))
            data = self.readn(csock, datasize)
            if flag & 0x8:
                data = inflate(data)
        remote = socket.create_connection((domain, port), timeout=8)
        if do_ssl_handshake:
            remote = ssl.SSLSocket(remote)
        if data:
            remote.sendall(data)
        forward_socket(csock, remote, timeout=60, bufsize=256*1024)


def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x: x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    server = TCPServer(('', 3389), password='123456')
    server.serve_forever()

if __name__ == '__main__':
    main()
