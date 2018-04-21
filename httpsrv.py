#!/usr/bin/env python
#encoding:utf8
# file upload and transfer by netwalker
import os, socket, sys, glob, datetime
import posixpath
import SimpleHTTPServer, BaseHTTPServer, SocketServer
import urllib, urlparse
import cgi
import shutil, thread, time
import mimetypes
import re, pdb, hashlib

g_cur_path = None
g_allow_ip = []
g_fake_srv = False
g_alive = time.time()
g_timeout = 60 * 2
httpd = None
g_first_ip = None
g_clients = []
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

def mymd5(buff):
    # if buff is a path of file
    if os.path.exists(buff):
        h = open(buff, 'rb')
        m = hashlib.md5()
        while True:
            mybuff = h.read( 102400 )
            if not mybuff:
                break
            m.update( mybuff )
        h.close()
    else:
        m = hashlib.md5()
        m.update(buff)

    return m.hexdigest()

class ThreadedHTTPServer( SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    BaseHTTPServer.HTTPServer.request_queue_size = 1

class SimpleHTTPRequestHandler( SimpleHTTPServer.SimpleHTTPRequestHandler ):
    def version_string( self ):
        return 'Ngix'
    def address_string(self):
        # it may block in log_message while resolve hostname, so skip resolve hostname
        host, port = self.client_address[:2]
        # return socket.getfqdn(host)
        return host
    def allowip( self ):
        global g_first_ip, g_timeout
        ip = self.client_address[0]
        if ip == '127.0.0.1': return True
        if not g_first_ip:
            g_first_ip = ip
            g_allow_ip.append( ip )
            print 'add allow ip', ip
            g_timeout = 60*60*4

        if g_allow_ip and ip not in g_allow_ip:
            print ip, 'forbbiden'
            return False
        return True

    def setup(self):
        global g_clients
        SimpleHTTPServer.SimpleHTTPRequestHandler.setup( self )
        if not self.allowip():
            class x:
                def readline( self, len=0):
                    return ''
                def close( self ):
                    pass
            self.rfile = x()
            self.requestline=''
            return
        global g_alive
        g_alive = time.time()
        self.sentsize  = '-'
        self.code = '-'
        g_clients.append( self.client_address )
    def finish(self):
        global g_clients

        self.log_request()
        if self.client_address in g_clients:
            g_clients.remove(self.client_address )
        SimpleHTTPServer.SimpleHTTPRequestHandler.finish( self )

    def send_head( self ):
        r = SimpleHTTPServer.SimpleHTTPRequestHandler.send_head( self )
        try:
            if r: self.sentsize = os.fstat(r.fileno())[6]
        except:
            r.seek(0,2)
            self.sentsize = r.tell()
            r.seek(0)
        return r
    def log_message(self, format, *args):

        sys.stderr.write("%s:%d %s %s\n" %
                         (self.client_address[0], self.client_address[1],
                          datetime.datetime.now().strftime('%H:%M:%S'),
                          format%args))
    def log_request(self, code='-', size='-'):
        if not hasattr( self, 'requestline' ) or not hasattr( self, 'code' ):
            return
        self.log_message('"%s" %s %s', ' '.join(self.requestline.split(' ', 3 )[:-1]) , str(self.code), str(self.sentsize))
    def do_GREP( self ):
        print 'grep'
        try:
            import cgi
            self._req  = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'GREP',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
        except:
            return self.send_error(500, 'BAD' )

        def grep(dname, keynames, exts=["*"], whole=False):
            ret = []
            def findkey( fname, keys, regx=True, whole=False ):
                ret = []
                txt = file(fname).read()
                codes = [ 'utf-8', 'gbk', 'latin' ]
                for code in codes:
                    try:
                        txt = txt.decode( code )
                        break
                    except:
                        pass
                lines = txt.split('\n')
                for i in xrange(len(lines)):
                    line = lines[i]
                    for key  in keys:
                        if regx:
                            if whole:
                                key = '\\b' + key + '\\b'
                            r = re.search( key, line )
                        else:
                            if whole:
                                r = key in line.split()
                            else:
                                r = key in line
                        if r:
                            if dname[-1] == '/': fnamex = f[len(dname):]
                            else: fnamex = f[len(dname)+1:]
                            if fnamex[0] == '/': fnamex = fnamex[1:]
                            ret.append( {'file':fnamex, 'line': i+1, 'content': line.rstrip() } )
                return ret

            for root, dirs, files in os.walk( dname ):
                for ext in exts:
                    result = glob.glob(os.path.join(root, ext ))
                    for f in result:
                        #print f
                        try:
                            ret += findkey( f, keynames, exts, whole=whole )
                        except:
                            pass
            #for fname, i, line in ret:
                #print '%s:%d %s' % ( fname, i, line )
            import json
            return  json.dumps( ret )
        tag = ','
        keynames = self._req['keys'].value.split(tag)
        exts = self._req['exts'].value.split(tag)

        #pdb.set_trace()
        whole = self._req['whole'].value == 'True'
        r = grep( self.translate_path(self.path), keynames, exts, whole=whole )
        self.sendResp( 200, r )

    def sendResp( self, code,  body ):
        f = StringIO()
        f.write( body )
        length = f.tell()
        f.seek( 0 )
        self.send_response(code)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        if f:
            self.copyfile(f, self.wfile)
            f.close()
        self.sentsize = length

    def send_response(self, code, message=None):
        #self.log_request(code)
        self.code = code
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("%s %d %s\r\n" %
                             (self.protocol_version, code, message))
            # print (self.protocol_version, code, message)
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())
    def do_POST(self):
        """Serve a POST request."""
        r, info = self.deal_post_data()

        path = self.translate_path(self.path)
        if g_fake_srv:
            error = False
            body = file( path ).read()
        elif r:

            error, body = self.listdirectory( path, status=info )
            body += '\n\n<UPLOAD OK>\n'
        else:
            self.sendResp( 500, info )
            return

        if error: body = info
        self.sendResp( 200, body )

    def deal_post_data(self):
        ischunk = False
        # pdb.set_trace()
        seek = 0
        if 'seek' in self.headers and self.headers['seek'] > 0:
            seek = int( self.headers['seek'] )
        
        try:
            boundary = self.headers.plisttext.split("=")[1]
        except:
            if 'transfer-encoding' in self.headers and self.headers['transfer-encoding'] == 'chunked':
                # is chunked
                line = self.rfile.readline()
                nlen = int( line.strip(), 16 )
                buf = self.rfile.read( nlen )
                ischunk = True
                filepath = None
                fname = self.headers['filepath']
                fn = os.path.join(g_cur_path, './' + fname )
                if g_cur_path not in fn:
                    print 'path strict [%s] [%s] ' % ( g_cur_path, fn  )
                    return False, 'path error now'

                # print 'path:[%s]' % fn
                out = open(fn, 'wb')
                out.write( buf )
                out.close()
                return (True, "<strong>File upload as '%s' OK!</strong>" % os.path.basename(fn) )
            else:
                nlen = int( self.headers['content-length'] )
                buf =  self.rfile.read( nlen )
                buf = buf.split('=', 1 )[1]
            # return ( True, 'done' )
        if 'expect' in self.headers : #and '100' in self.headers['expect']:
            self.wfile.write( 'HTTP/1.0 100 Continue\r\n\r\n' )

        filemd5 = ''
        try:
            filemd5 = self.headers['filemd5']
        except:
            pass
        filepath = ''
        try:
            filepath = self.headers['filepath']
        except:
            pass

        remainbytes = int(self.headers['content-length'])
        line = self.rfile.readline()
        remainbytes -= len(line)
        if not boundary in line:
            return (False, "Content NOT begin with boundary")
        line = self.rfile.readline()
        remainbytes -= len(line)
        if True:
            fn = re.findall(r'Content-Disposition.*name="file"; filename="(.*)"', line)
            if not fn:
                return (False, "Can't find out file name...")

            path = self.translate_path(self.path)

            fname = fn[0]
            if '\\' in fname: fname = fname[ fname.rfind('\\')+1:]
            if not fname: return ( False, 'select your  upload file' )
            if not filepath:
                fn = os.path.join( path,  fname )
            else:
                import platform
                if platform.system() == 'Windows':
                    filepath = filepath.replace( '/', '\\' )
                fn = os.path.join( g_cur_path, filepath )
                #print g_cur_path, os.path.dirname( os.path.realpath( fn ) )
                # /./././
                while '/./' in fn: fn = fn.replace('/./','/')
                while '/../' in fn: fn = fn.replace('/../','/')
                p = os.path.dirname( fn )
                if not os.path.exists( p ) or  g_cur_path not in p:
                    return ( False, 'path error' )

        ofn = fn[:]

        line = self.rfile.readline()
        remainbytes -= len(line)
        line = self.rfile.readline()
        remainbytes -= len(line)
        try:
            if seek > 0:
                if os.path.exists(fn) and  os.lstat( fn ).st_size != seek:
                    out = open( fn, 'wb' )
                else:
                    out = open( fn, 'ab+' )
                #out.seek( seek )
            else:
                out = open(fn, 'wb')
        except IOError:
            print 'error file write'
            import traceback
            traceback.print_exc()
            return (False, "Can't create file to write, do you have permission to write?")

        preline = self.rfile.readline()
        remainbytes -= len(preline)
        curmd5 = hashlib.md5()
        while remainbytes > 0:
            line = self.rfile.readline()
            remainbytes -= len(line)
            if boundary in line:
                preline = preline[0:-1]
                if preline.endswith('\r'):
                    preline = preline[0:-1]
                out.write(preline)
                curmd5.update( preline )
                out.close()
                if filemd5:
                    #
                    x = curmd5.hexdigest()
                    if x == filemd5 and fn != ofn:
                        print 'same md5, right file'
                        shutil.copyfile( fn, ofn )
                        fn = ofn
                return (True, "<strong>File upload as '%s' OK!</strong>" % os.path.basename(fn) )
            else:
                out.write(preline)
                curmd5.update( preline )
                preline = line
        print 'error end file', preline
        return (False, "Unexpect Ends of data.")

    def listdirectory(self, path, status='' ):
        error = False
        r = ''
        try:
            dlist = os.listdir(path)
        except os.error:
            error = True
            r = 'No permission to list directory'
            return error, r

        dlist.sort(key=lambda a: a.lower())
        f = StringIO()
        displaypath = cgi.escape(urllib.unquote(self.path))

        r = '''
        <html>
        <head><meta content="text/html; charset=utf-8" http-equiv="content-type" /><title>List of %s</title></head>
        <body>
        %s <br>
        <table>
        <th> <form ENCTYPE="multipart/form-data" method="post"> <input name="file" type="file" /> <input type="submit" value="upload file"/> </form> </th>
        <th>&nbsp;&nbsp;&nbsp;&nbsp;</th>
        <th> <form  method="post" enctype="text/plain"> <textarea name="txt" ></textarea> <input type="submit" value="Message Send"/> </form> </th>
       </table> \n%s\n </body></html> '''
        body = ''

        dirs = []
        files = []

        for name in dlist:
            fullname = os.path.join(path, name)
            displayname = linkname = name

            if os.path.isdir(fullname):
                dirs.append( name )
            else:
                files.append( name )
        dirs.sort()
        files.sort()
        ua = self.headers.get('User-Agent', "")
        body = ''
        if 'curl' in ua:
            r = '\n'.join( [ '%s/' % d for d in dirs ] +  files )
        else:
            body = '\n'.join( [ '''<li><a href="%s/">%s/</a> \n ''' % ( urllib.quote(d), cgi.escape(d) ) for d in dirs ] +
               ['<br><br>'] + ['''<li><a href="%s">%s</a> \n ''' % ( urllib.quote(f), cgi.escape(f) ) for f in files ] )
            body += "</ul>\n<hr>\n</body>\n</html>\n"

            r = r % ( displaypath, status , body )
        return error, r

    def list_directory(self, path):
        error, body = self.listdirectory( path )
        if error:
            self.send_error(404, body )

        f = StringIO()
        f.write( body )
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.send_header( "ISDIR", "true" )
        self.end_headers()
        return f



    def translate_path(self, path):
        if os.path.isfile( g_cur_path):
            return g_cur_path

        # from SimpleHTTPServer.py
        path = path.split('?',1)[0]
        path = path.split('#',1)[0]
        # Don't forget explicit trailing slash when normalizing. Issue17324
        trailing_slash = path.rstrip().endswith('/')
        path = posixpath.normpath(urllib.unquote(path))
        words = path.split('/')
        words = filter(None, words)
        path = g_cur_path[:] # hacking here
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir): continue
            path = os.path.join(path, word)
        if trailing_slash:
            path += '/'

        #path = SimpleHTTPServer.SimpleHTTPRequestHandler.translate_path( self, path  )

        if g_fake_srv:
            path =  os.path.basename( path )
            if not path:
                path = '/'
        if path[-1] == '/' and os.path.exists(  'index.html'  ):
            path = 'index.html'
        return path

def server_bind(self):
    """Override server_bind to store the server name."""
    SocketServer.TCPServer.server_bind(self)
    host, port = self.socket.getsockname()[:2]
    self.server_name = 'localhost'
    self.server_port = port
BaseHTTPServer.HTTPServer.server_bind = server_bind


def test(HandlerClass = SimpleHTTPRequestHandler,
         ServerClass = BaseHTTPServer.HTTPServer, protocol="HTTP/1.0"  ):
    global g_cur_path, g_allow_ip, g_fake_srv, httpd
    port = 8000
    g_cur_path = os.getcwd()
    fname = ''
    usessl = False
    try:
        import urllib2
        timeout = 30
        #print sys.argv
        i = sys.argv.index( '-f' ) 
        if i<0: raise -1
            
        localfile = sys.argv[i+1]
        sys.argv.pop( i )
        sys.argv.pop( i )
        url = sys.argv[1]
        #print 'url', url, 'file', localfile
        # get remote file size
        r = urllib2.Request( url + '/' + os.path.basename(localfile) )
        r.get_method = lambda : 'HEAD'
        try:
            res = urllib2.urlopen(r)
            size = int( res.headers['Content-Length'] ) 
            
        except:
            size = 0
        localsize = os.lstat( localfile ).st_size
        #print 'size', size, localsize
        n = 0
        def do_put( url, localfile, start = 0, maxsize=1024 * 1024 * 100  ):
            size = maxsize
            fd = open( localfile, 'rb' )
            fd.seek( start )
            buf = fd.read( maxsize )
            size = len(buf)
            #print 'to send size', size
            boundary = '----WebKitFormBoundaryI8ck2vA2P6cqVRq2'
            sep_boundary = '--' + boundary
            end_boundary = sep_boundary + '--' + '\r\n'
            s = '%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n' % ( 
                sep_boundary, 
                'file', 
                os.path.basename( localfile ) 
            ) + buf + '\r\n' + end_boundary
            s = s.decode('latin').encode('latin')
            #print 'xx', repr( s )
            headers = {}
            headers['Content-type'] = 'multipart/form-data; boundary=%s' % boundary
            headers['Content-length'] = str( len(s) )
            headers['seek'] = str(start)
            req = urllib2.Request( url.encode('utf8'), s, headers )
            if s: req.add_data( s )
            for i in xrange( 3 ):
                try:
                    
                    obj = urllib2.urlopen( req, timeout = timeout )
                    head = obj.info().headers
                    response = obj.read()
                    if not response: raise 0
                    return size
                    break
                except urllib2.HTTPError,  err:
                    if err.code in [301,302]:
                        break
                except:
                    pass
            
            return 0
            #return size
        
        while size<localsize and n < 50:
            ret = do_put( url, localfile, start=size )
            #print 'ret =', ret, 'size=', size
            if ret == 0:
                n += 1
            else:
                n = 0
                size += ret 
        
        
        # append now 
        print 'upload ok'
        return
    except:
        #import traceback
        #traceback.print_exc()
        pass
    for a in sys.argv[1:]:
        try:
            port = int( a )
        except:
            if os.path.exists( a ):
                g_cur_path = a
                if os.path.isfile( a ):
                    fname = os.path.basename( a )
            elif a == 'fakesrv':
                g_fake_srv = True
            elif a == 'usessl':
                usessl = True
            else:
                g_allow_ip.append( a )

    server_address = ('0.0.0.0', port)
    HandlerClass.protocol_version = protocol
    httpd = ThreadedHTTPServer(server_address, HandlerClass)
    import ssl
    if usessl:
        c = '''
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDEBgoEi5Ih3dgJ
oDOpl4+moElDvqHxk7eXTo8gQyZrO130Fh9J1VPkDHM33QVHuKePCmZBNRk37Yj8
k9ggk6zGvAkQPdGYli0AdzhYil8j47utezDSbXGyRJrINqntTQ9SnqkxMePrOuum
bJEwUwjE0M8Hjc0W39ybXqo0bKgqzqkdwhjr7LCIGlEOq6kW8hHM3Wtu5i1vEFyp
STzRyCEAZ0l9jmF3QaG86ZMaNrBGLtHkAc9xg2qtaCup8ktG41t78OQYENyrA11c
IgWdV6ebH2gzpH+2DVRt1nOa26he01aFjHJu8nz3J5aBJ+2F5Vu7FZrHNbTZoNot
NjPyzX2XAgMBAAECggEBAKznIsj1j1VeB+QdsdQigqwX7+fYa6HZiPPmcGqlsGqf
d/UH2ltW1uNtc+fPhYvIvct3AdD8lBz34X/grJ+3govdaiUwUgNEW7dwcXvvuZG/
m1ifM+Y4cTQsPVbimKpe8WgP2O8ysXZYh2lJlBtK8o4gHKzuD/vgRAerzXfma8Ms
8Vx06HeASK2C4NZburPLHpF9ENHk2cpragKmB8SGfEXRcxOosK+OhIal+pKDT+Zq
0iRtWCjy0KWuAcOPDNcQE+jFN/EfNQdpvwyf65dPs9gPOMcSH/9bnXJZtvendwMH
Jt2vXaqIYsSbcmc4KaC1vGynjyvAbBk3DRmjisiDq0ECgYEA4g4dLLIrpBiJO5JL
eshr6DN8dHZpyoaCUhh1U/avuf9SY6B6Pph287KjbZeVaV5m/WtUn/gsJCo3YClQ
M+Sj8+BmIreWMy3zU/FGAtfJnycg0/zJxCIU1TOJL+Tk3vmZYpfMZBiZfSyyJxVi
w9SayB53I+y7EHX2K2m05ir8hyECgYEA3f2CGgBiM7RZIwOSX6JBTBlfrdjRpVOI
r25FkycI3RFGCGxgx3yKGkgRRflAynA3SOMxms+3DrX3GRwlb3HQdztrk0vocLG+
1Cvr2cjdtd71+r8pGqbnhNR51hOUygx0rhduNfbXfWyAiZqakee/UQStHVe1+MkQ
7DhCq1U9RbcCgYEAtt+oJnJ076mRy4mMWmYtNYoBUs5Aw0CRyQxUTnqwqo2s/z/h
5SW+hWOs5onMq5NdSgI8UbWZMCCe78I8Sd7b6/1LYyaV8g1oXi4/7yjWyVQEMLq+
F1di9x9cCkzoAqJ1vdcD2K417Zfs/8VDQx2Jof9TbtKieqyTW4eGevWnmUECgYEA
zeMkelcmvUukbGwQovAK3bie288/SbW7DPIaR0up1dcCfCeAbyRbtdpnYt21MMx5
CfnldO73mgY8oiZPthf6P8t1j4yUjYjdM011Fm1M7DRZMXGAfv6TtceXJGzOz8JT
qW+DwTsqS2KJqJYii/ZDo7HRmWhTFuXs8xmPA/cvt+sCgYAyKzNH1TIYlvLJLlc3
mPpJcOtK96IqY1x/BrcbJRDxNUhd2DelYoxpAV4zOD/AWm9428tSbuHNT3vNnRIo
74N+/FzzhAYgobMEErDJ9aIFlPnKLnp4XlMQaMNi/mQEWUPo6F1E73GQVgCjeYto
j/Xa/rc6x5ectXd2qrWmgX1/Ew==
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIID+TCCAuGgAwIBAgIJAJotubPQirx0MA0GCSqGSIb3DQEBCwUAMIGSMQswCQYD
VQQGEwJDTjERMA8GA1UECAwISGFuZ1pob3UxDzANBgNVBAcMBll1SGFuZzEVMBMG
A1UECgwMQWxpYmFiYSBpbmMuMRcwFQYDVQQLDA5DL0NQUCBTZWN1cml0eTEVMBMG
A1UEAwwMMTAuMS4xNTcuMjEwMRgwFgYJKoZIhvcNAQkBFgl6ZEB4eC5jb20wHhcN
MTUwODIxMDcxNTI2WhcNMTYwODIwMDcxNTI2WjCBkjELMAkGA1UEBhMCQ04xETAP
BgNVBAgMCEhhbmdaaG91MQ8wDQYDVQQHDAZZdUhhbmcxFTATBgNVBAoMDEFsaWJh
YmEgaW5jLjEXMBUGA1UECwwOQy9DUFAgU2VjdXJpdHkxFTATBgNVBAMMDDEwLjEu
MTU3LjIxMDEYMBYGCSqGSIb3DQEJARYJemRAeHguY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAxAYKBIuSId3YCaAzqZePpqBJQ76h8ZO3l06PIEMm
aztd9BYfSdVT5AxzN90FR7injwpmQTUZN+2I/JPYIJOsxrwJED3RmJYtAHc4WIpf
I+O7rXsw0m1xskSayDap7U0PUp6pMTHj6zrrpmyRMFMIxNDPB43NFt/cm16qNGyo
Ks6pHcIY6+ywiBpRDqupFvIRzN1rbuYtbxBcqUk80cghAGdJfY5hd0GhvOmTGjaw
Ri7R5AHPcYNqrWgrqfJLRuNbe/DkGBDcqwNdXCIFnVenmx9oM6R/tg1UbdZzmtuo
XtNWhYxybvJ89yeWgSftheVbuxWaxzW02aDaLTYz8s19lwIDAQABo1AwTjAdBgNV
HQ4EFgQUUd9K8a1AGzXBpptgPW1QQkNcumwwHwYDVR0jBBgwFoAUUd9K8a1AGzXB
pptgPW1QQkNcumwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAg9C2
j8wSVomfsU4Luz5mksNgOZts3WUVBDjXwIq55OHDXU3We5l/6fvfJ/hc3KRe0J0L
/Miwh1rT1ARCTd1EB+MDR4jwIO3gTNHSswbLa8ZvsN71zguzhLS5z5McPxcSW7lJ
Em3FNiIp4LPocXhTkkrg7r79lKTBSz5QHvhI/wCPgJBg+rjPQ6nZTI2xT1u3kCTV
U3XhwO/E++pO/hZ/el0B0Wh21pKSCxEwsuMuUHALsyuIcoMNngIt2A9Jr+kOQ3re
PEDVfm36EMYm3NK7B+43t1VG5cyTZoemij7d+rlT9Qqh0gFzOXc8A1YHPP6RY/zG
BxXpCIejJKlHavTMvw==
-----END CERTIFICATE-----
        '''
        try:
            cf = '/tmp/server.pem'
            if platform.system() == 'Windows': cf = 'serverhttps.pem'
            fd = open( cf, 'w' )
            fd.write( c )
            fd.close()
            httpd.socket = ssl.wrap_socket (httpd.socket, certfile=cf, server_side=True)
        except:
            print 'Failed to usessl'
            usessl = False
    import platform
    ips = []
    if platform.system() == 'Windows':
        try:
            sa = socket.gethostbyname(socket.gethostname())
        except:
            sa = '0.0.0.0'
        ips.append( sa )
    else:
        import commands
        r = commands.getoutput( 'ip addr' )
        ips = re.findall( 'inet ([\d\.]+)/', r )
#ips.remove( '127.0.0.1' )

    ips.append('0.0.0.0')
    for ip in ips:
        h = 'https' if usessl else 'http'
        print "Serving on %s://%s:%d/%s" % ( h, ip, port, fname  )
    if not fname:
        print 'working dir:', g_cur_path
        print '\nupload file: curl -F file=@file $URL\t\t (filemd5 filepath)'
        # print "\nupload file:", 'curl -F file=@"$file"  %s://%s:%d' % ( h, ips[0], port )
        #print 'filemd5 filepath'
    if g_allow_ip: print 'allow ip:', ' ,'.join( g_allow_ip )

    thread.start_new_thread( exitthread, () )

    try:
        httpd.serve_forever()
    except:
        pass
def exitthread():
    global g_alive, httpd, g_clients
    while True:
        time.sleep( 1 )
        if time.time() - g_alive > g_timeout:
            if len(g_clients):
                print g_clients
            break
    print datetime.datetime.now().strftime('%H:%M:%S'), 'run timeout', time.time() - g_alive
    httpd.server_close()

if __name__ == '__main__':
    test()
