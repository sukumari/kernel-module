import socket

def scan(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        print("Port open: " + str(port))
        s.close()
    except:
        print("Port closed: " + str(port))

host = "10.10.10.1"
for port in [21, 22, 80]:
    scan(host, port)
