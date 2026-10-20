import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", int(sys.argv[1])))
while True:
    data, addr = s.recvfrom(65535)
    s.sendto(data, addr)
