import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(sys.argv[3].encode(), (sys.argv[1], int(sys.argv[2])))
try:
    print(s.recv(65535).decode())
except socket.timeout:
    sys.exit(1)
