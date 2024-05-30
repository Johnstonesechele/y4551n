import pyfiglet
import sys
import socket
from datetime import datetime

ascii_banner = pyfiglet.figlet_format("YASSIN SCANNER")
print(ascii_banner)

if len(sys.argv) == 2:
    target = socket.gethostbyname(sys.argv[1])
else:
    print("Invalid amount of arguments; you must provide an IP")

print("-" * 80)
print("Scanning Target: " +target)
print("Scanning Target at: " + str(datetime.now()))
print("-" * 80)

try:
    for port in range(1,100):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(40)

        result = s.connect_ex((target,port))
        if result == 0:
            print("Port {} is open".format(port))
        s.close()

except KeyboardInterrupt:
    print("\n Exitting Program .......")
    sys.exit()
except socket.gaierror:
    print("\n Hostname Could Not Be Resolved !!!!!")
    sys.exit()
except socket.error:
    print("\n Server Not Responding !!!!")
    sys.exit()