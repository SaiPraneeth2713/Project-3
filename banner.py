import socket

def banner(ip, port):

    try:

        sock = socket.socket()

        sock.settimeout(2)

        sock.connect((ip, port))

        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = sock.recv(1024)

        return banner.decode(errors="ignore")

    except:

        return "No Banner"