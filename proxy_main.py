# import required library files
import socket
import threading
import ssl
import time

# importing my custom modules
import filter
from duplicate_target_server_certi import DuplicateCerti

'''
Plan:
    #Proxy Start() [Accept Connection]
    1. Accept connection from client and start the thread #handle_client
    
    #handle_client
    1. Recieve, Parse Request and check if target server is blocked using "filter.isBlock()"
    2. If block close connection else proceed
    3. If HTTP --> #relayComm else #makeSecureRelay [Perform CONNECT]
    4. #relayComm through secure sockets (client and target server)

    #makeSecureRelay [Perform CONNECT]
    1. SSL handshake with target server with the help of "ca-bundle.pem"
    2. #Generate Duplicate Target Server Certi using "duplicate_target_server_certi.DuplicateCerti" module
    3. Send 200 Ok in response of CONNECT request
    4. SSL handshake with client using the duplicate_certi(stored in "./certs/") of target server and keyfile of rootCA.key (Read about OCSP)
    [Note]: ca-bundle.pem generated using "ssl_certi.sh"

    #Generate Duplicate Target Server Certi
    1. Get target server certi info
    2. Generate new certi of target server(#duplicateCerti) and set the properties as per retrieved info using x509.CertificateBuilder()
    3. Sign it with rootCA(rootCA must be installed in browser's trusted root certi store)
    4. Save duplicate certi in ./certs/
    [Note]: rootCA.pem and rootCA.key generated using "ssl_certi.sh"

    #relayComm
    1. Relay communication between target server and client using getData() and sendData()
    2. Keep relaying until request from client contains "Connection:close" header or response from server contains "Keep-Alive:timeout=5"


'''

class ProxyServer:
    C_sockets=[]
    S_sockets=[]
    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port

    def start(self):
        # server socket to accept clients
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # allow reuse of a local address when the socket is no longer in use
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen()

        while True:
            client_socket, client_address = self.server.accept()
            print('[*] Recieved request from :',client_address)
            # Threading to handle client's socket connection
            proxy_thread = threading.Thread(
                target=self.handle_client, args=(client_socket, client_address))
            proxy_thread.start()

    # handle client's connection
    def handle_client(self, client_socket, client_address):

        # Recieve Request from client
        request,releaseConnection=self.getData(client_socket)
        # Handle recieved request
        if(request==b'' or releaseConnection):
            print('[*] Closing Conection:',client_address)
            client_socket.shutdown(socket.SHUT_RDWR)
            client_socket.close()
            return

        decoded_request = request.decode(errors='ignore')
        # print(decoded_request)
        # Extract the URL from the request
        url = decoded_request.split(' ')[1]
        method = decoded_request.split(' ')[0]
        targetServer, port, path = self.get_targetServer_port_path(url)

        # check for blocked sites written in "filter.py" module
        status=filter.isBlock(targetServer)
        if (type(status)==bool and status==True):
            client_socket.sendall("HTTP/1.1 403 Forbidden\r\n\r\n".encode())
            client_socket.close()
        elif(type(status)==int and status==-1):
            client_socket.sendall("HTTP/1.1 404 Not Found\r\n\r\n".encode())
            client_socket.close()

        # Connect to the requested targetServer
        else:  # handle CONNECT
            if (port == 443):
                # Handling Proxy CONNECT method
                if (method == 'CONNECT'):        
                    # make ssl secure relay
                    print(decoded_request)
                    server_socket, client_socket = self.makeSecureRelay(client_socket, targetServer)
                    if(server_socket==-1):
                        # Secure Connection Failed
                        client_socket.sendall("HTTP/1.1 200 OK\r\n\r\n".encode())
                        # request = client_socket.recv(1024)
                        client_socket.sendall("HTTP/1.1 200 OK\r\n\r\nSecure Connection Failed".encode())
                        client_socket.shutdown(socket.SHUT_RDWR)
                        client_socket.close()
                        print('except')
                                    
                        return
                        
                else:
                    # Send a bad request status code to the browser for other than CONNECT before making relay connection
                    client_socket.sendall("HTTP/1.1 400 BAD REQUEST\n\n".encode())
                    client_socket.close()

            # if protocol is HTTP it don't need CONNECT
            elif (port == 80):
                # proxy socket to connect targetServer
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect((targetServer, 80))
                print('[*] Connected to server :',targetServer)

            # relay the communication between client and targetServer
            self.relayComm(server_socket, client_socket, request, method, client_address, targetServer)
            # print("\n[*] Remaining C_Socket:",self.C_sockets,"\n[*] Remaining S_Socket:",self.S_sockets)

    # retrieve targetServer, port and path from url
    def get_targetServer_port_path(self, url):
        if url.startswith("http://"):
            url = url[7:]
            port = 80
        elif url.startswith("https://"):
            url = url[8:]
            port = 443

        if ":" in url:
            path, port = url.split(':')
            targetServer = path.split('/')[0]
            return targetServer, int(port), path
        else:
            path = url
            targetServer = path.split('/')[0]
            return targetServer, port, path

    # Establishing MITM connection for HTTPS
    def makeSecureRelay(self, client_socket, targetServer):
        try:
            # PROTOCOL_TLS_CLIENT requires valid cert chain and host name
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations('./certs/ca-bundle.pem')
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(5)
            server_socket.connect((targetServer, 443))
            print('[*] Connected to server :',targetServer)
            server_ssl_socket = context.wrap_socket(server_socket,server_hostname=targetServer)
        except :
            return -1, client_socket
        # duplicate target server certi
        DuplicateCerti.generate(server_ssl_socket,targetServer)

        # send a 200 OK response to the client to establish the tunnel [Must be sent before securing client socket]
        client_socket.sendall("HTTP/1.1 200 OK\r\n\r\n".encode())

        # Create a new SSL context and wrap the client socket
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=f'./certs/{targetServer}.pem',keyfile='./certs/rootCA.key',password=None)
        client_socket.settimeout(5)
        client_ssl_socket = context.wrap_socket(client_socket,server_side=True)

        return server_ssl_socket,client_ssl_socket

    # relaying the communication between client and target server
    def relayComm(self, server_socket, client_socket, request, method, client_address, target_server):
        # Forward data between the browser and the destination server
        if (method!='CONNECT'):     # if method is not CONNECT that means we are dealing with HTTP, and we already have got the request for it
            response=b''
            # handling recieved request
            if(request!=b''):
                # Send Request to target server
                releaseConnection=self.sendData(server_socket,request)
                # Recieve Response from target server
                response,releaseConnection=self.getData(server_socket)
            # handling recieved response
            if(response!=b''):
                # send Response to client
                releaseConnection=self.sendData(client_socket,response)
                # releaseConn if "Connection:close" in headers
                headers=response.split(b'\r\n\r\n')[0]
                releaseConnection=self.releaseConn(headers)

        self.C_sockets.append(client_socket)
        self.S_sockets.append(server_socket)
    
        # while connection does not get release relay comm
        timeout=5
        last_activity = time.time()
        releaseConnection=False
        while not releaseConnection and not time.time() - last_activity > timeout:
            response=b''
            # Recieve Request from client
            request,releaseConnection=self.getData(client_socket)

            # handling recieved request
            if(request!=b''):
                # Send Request to target server
                releaseConnection=self.sendData(server_socket,request)
                # Recieve Response from target server
                response,releaseConnection=self.getData(server_socket)
                headers=request.split(b'\r\n\r\n')[0]
                # print(threading.get_native_id(),"Request:",headers)
                last_activity = time.time()
            # handling recieved response
            if(response!=b''):
                # send Response to client
                releaseConnection=self.sendData(client_socket,response)
                # releaseConn if "Connection:close" in headers
                headers=response.split(b'\r\n\r\n')[0]
                releaseConnection=self.releaseConn(headers)
                # print(threading.get_native_id(),"Response:",headers)

        # Close the connections when releaseConnection==True
        self.C_sockets.remove(client_socket)
        self.S_sockets.remove(server_socket)
        print(threading.get_native_id(),releaseConnection,'[*] Closing Conection:',client_address,target_server)
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
            client_socket.close()
            server_socket.shutdown(socket.SHUT_RDWR)
            server_socket.close()
        except Exception as e:
            print('Exception in closing connection : ',e)

    # recieve data from server/client
    def getData(self,sock):
        # Recieve data
        sock.settimeout(2)
        releaseConnection=False
        recvData = b''
        while True:
            try:
                data = sock.recv(1024)
                if data==b'':
                    # print('Breaking',threading.get_native_id())
                    break
            except ConnectionResetError:    # Connection Reset by host
                # Close the host connections
                releaseConnection=True             
                break
            except socket.timeout:
                break
            recvData += data

        # print(recvData)
        return recvData, releaseConnection

    # send data to server/client
    def sendData(self,sock,data):
        releaseConnection=False
        try:
            sock.sendall(data)
        except BrokenPipeError:
            releaseConnection=True
        return releaseConnection

    def releaseConn(self,headers):
        if b'Connection: Close' in headers:
            return True
        elif b'Connection: keep-alive' in headers:
            return False
        elif b'Keep-Alive: timeout' in headers:
            return True # handle last_activity param and releaseConn properly
            
if __name__ == '__main__':
    proxy_server = ProxyServer()
    proxy_server.start()    # start proxy server
