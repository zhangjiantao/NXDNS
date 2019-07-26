#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import logging
import struct
import socket
import psutil

if sys.version_info.major == 2:
    import thread
    import SocketServer
else:
    import _thread as thread
    import socketserver as SocketServer


# DNS Query
class SinDNSQuery:
    def __init__(self, data):
        i = 1
        self.name = ''
        while True:
            d = ord(data[i])
            if d == 0:
                break
            if d < 32:
                self.name = self.name + '.'
            else:
                self.name = self.name + chr(d)
            i = i + 1
        self.querybytes = data[0:i + 1]
        (self.type, self.classify) = struct.unpack('>HH', data[i + 1:i + 5])
        self.len = i + 5

    def getbytes(self):
        return self.querybytes + struct.pack('>HH', self.type, self.classify)


# DNS Answer RRS
# this class is also can be use as Authority RRS or Additional RRS
class SinDNSAnswer:
    def __init__(self, ip):
        self.name = 49164
        self.type = 1
        self.classify = 1
        self.timetolive = 190
        self.datalength = 4
        self.ip = ip

    def getbytes(self):
        res = struct.pack('>HHHLH', self.name, self.type, self.classify, self.timetolive, self.datalength)
        s = self.ip.split('.')
        res = res + struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
        return res


# DNS frame
# must initialized by a DNS query frame
class SinDNSFrame:
    def __init__(self, data):
        (self.id, self.flags, self.quests, self.answers, self.author, self.addition) = struct.unpack('>HHHHHH',
                                                                                                     data[0:12])
        self.query = SinDNSQuery(data[12:])

    def getname(self):
        return self.query.name

    def setip(self, ip):
        self.answer = SinDNSAnswer(ip)
        self.answers = 1
        self.flags = 33152

    def getbytes(self):
        res = struct.pack('>HHHHHH', self.id, self.flags, self.quests, self.answers, self.author, self.addition)
        res = res + self.query.getbytes()
        if self.answers != 0:
            res = res + self.answer.getbytes()
        return res


# A UDPHandler to handle DNS query
class SinDNSUDPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        dns = SinDNSFrame(data)
        namemap = SinDNSServer.namemap
        if dns.query.type == 1:
            # If this is query a A record, then response it
            name = dns.getname()
            toip = None
            ifrom = "map"
            if namemap.__contains__(name):
                # If have record, response it
                toip = namemap[name]
            elif namemap.__contains__('*'):
                # Response default address
                toip = namemap['*']
            else:
                # ignore it
                try:
                    toip = socket.getaddrinfo(name, 0)[0][4][0]
                    ifrom = "sev"
                except Exception as e:
                    logging.error(e)
            if toip:
                dns.setip(toip)
            logging.info('[DNS] %s: %s --> %s (%s)' % (self.client_address[0], name, toip, ifrom))
            self.request[1].sendto(dns.getbytes(), self.client_address)
        else:
            self.request[1].sendto(data, self.client_address)


# DNS Server
# It only support A record query
# user it, U can create a simple DNS server
class SinDNSServer:
    def __init__(self, addr='0.0.0.0', port=53):
        SinDNSServer.namemap = {}
        self.addr = addr
        self.port = port

    def addname(self, name, ip):
        SinDNSServer.namemap[name] = ip
        logging.info('[DNS] bind addr %s to %s' % (name, ip))

    def start(self):
        logging.info('[DNS] start dns server on %s:%d' % (self.addr, self.port))
        server = SocketServer.UDPServer((self.addr, self.port), SinDNSUDPHandler)
        server.serve_forever()


# A TCPHandler to handle HTTP request
class SinHTTPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024).strip().decode('utf-8')
        logging.info('[HTTP] request from (%r):%r' % (self.client_address, data))
        if data.find('Host: conntest.nintendowifi.net\r\n') != -1:
            response_body = '''
            <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
            <html>
            <head>
            <title>HTML Page</title>
            </head>
            <body bgcolor="#FFFFFF">
            This is test.html page
            </body>
            </html>
          '''
        elif data.find('Host: ctest.cdn.nintendo.net\r\n') != -1:
            response_body = 'ok'
        else:
            response_body = '''What's your problem?'''
        response_headers = 'HTTP/1.0 200 OK\r\nContent-Length: %d\r\n' % len(response_body)
        response_headers += 'Content-Type: text/html\r\nX-Organization: Nintendo\r\n\r\n'
        response = response_headers + response_body
        self.request.sendall(response.encode('utf-8'))


# HTTP Server
class SinHTTPServer:
    def __init__(self, addr='0.0.0.0', port=80):
        self.addr = addr
        self.port = port

    def start(self):
        logging.info('[HTTP] start http server on %s:%d' % (self.addr, self.port))
        server = SocketServer.TCPServer((self.addr, self.port), SinHTTPHandler)
        server.serve_forever()


# PSUTIL
class psutils:
    @staticmethod
    def get_active_netcards():
        netcard_info = []
        info = psutil.net_if_addrs()
        for k,v in info.items():
            for item in v:
                if item[0] == 2 and item[1] != '127.0.0.1' and item[1][:8] != '169.254.':
                    netcard_info.append((k,item[1]))
        return netcard_info

    @staticmethod
    def get_addr():
        info = psutils.get_active_netcards()
        if len(info) == 1:
            return info[0][1];
        else:
            while True:
                for i in range(len(info)):
                    print("    <%d>: %s %s" % (i, info[i][1], info[i][0]))
                id = input('which? >')
                try:
                    idx = int(id)
                    if idx < len(info):
                        return info[idx][1]
                except:
                    pass


def StartDNSServer(addr, port):
    sev = SinDNSServer(addr, port)
    sev.addname('*', '0.0.0.0')  # block all
    sev.addname('ctest.cdn.nintendo.net', addr)  # add a A record
    sev.addname('conntest.nintendowifi.net', addr)  # add a A record
    sev.addname('test.test.test', addr)  # add a A record
    sev.addname('test.test', addr)  # add a A record
    sev.start()


def StartHTTPServer(addr, port):
    sev = SinHTTPServer(addr, port)
    sev.start()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        addr = psutils.get_addr()
        logging.info("start on %s" % addr)
        thread.start_new_thread(StartDNSServer, (addr, 53))  # start DNS server
        thread.start_new_thread(StartHTTPServer, (addr, 80))  # start HTTP server
    except Exception as e:
        logging.error(e)

    while True:
        pass
