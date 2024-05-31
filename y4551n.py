import pyfiglet
import nmap
import socket
import datetime
import ipaddress
import signal
import subprocess
import threading

ascii_banner = pyfiglet.figlet_format("y4551n")
print(ascii_banner)

def timeout_handler(signum, frame):
    raise TimeoutError("Session timeout.")

def ping_host(target):
    try:
        subprocess.run(["ping", "-c", "1", target], check=True)
        print(f"The host {target} is reachable.")
    except subprocess.CalledProcessError:
        print(f"The host {target} is not reachable.")

def service_version_detection(target, port, scan_type):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Adjust timeout as needed

        sock.connect((target, port))
        sock.send(b'HELLO\r\n')  # Send a sample request for banner grabbing
        response = sock.recv(1024).decode('utf-8')

        print(f"Service version on port {port}/{scan_type.upper()}: {response.strip()}")
    except Exception as e:
        print(f"Error while detecting service version on port {port}/{scan_type.upper()}: {e}")
    finally:
        sock.close()

def os_scan(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-O')

        if nm[target].state() == 'up':
            if 'osclass' in nm[target]:
                print(f"\nOS detected on {target}: {nm[target]['osclass'][0]['osfamily']}")
            else:
                print(f"\nUnable to detect OS on {target}.")
        else:
            print(f"\nThe host {target} is down.")

    except nmap.nmap.PortScannerError as e:
        print(f"Error while performing OS fingerprinting: {e}")
    except Exception as e:
        print(f"Unexpected error during OS fingerprinting: {e}")

def open_msfconsole():
    try:
        subprocess.run(['msfconsole'])
    except Exception as e:
        print(f"Error opening msfconsole: {e}")

def scan_ports(target, port_range, scan_type, speed, timeout):
    open_ports = []

    try:
        ipaddress.ip_address(target)
    except ValueError:
        print("Error: Invalid IP address. Please enter a valid IP.")
        return

    try:
        start_port, end_port = map(int, port_range.split('-'))
    except ValueError:
        print("Error: Invalid port range. Please enter a valid range (e.g., 1-100).")
        return

    if not (0 < start_port <= end_port <= 65536):
        print("Error: Port range must be between 1 and 65536.")
        return

    socket_type = socket.SOCK_STREAM if scan_type.lower() == 'tcp' else socket.SOCK_DGRAM
    scan_speed = {'T1': 0.5, 'T2': 0.3, 'T3': 0.1, 'T4': 0.05, 'T5': 0.01}

    if scan_type.lower() not in ['tcp', 'udp']:
        print("Error: Invalid port type. Please enter 'tcp' or 'udp'.")
        return

    if speed.upper() not in scan_speed:
        print("Error: Invalid scan speed. Please enter 'T1', 'T2', 'T3', 'T4', or 'T5'.")
        return

    start_time = datetime.datetime.now()
    print(f"\nScan started at {start_time}.")

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)  # Set the timeout

    try:
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=scan_port, args=(target, port, scan_type, scan_speed[speed],))
            t.start()

        # Wait for all threads to finish
        for thread in threading.enumerate():
            if thread != threading.current_thread():
                thread.join()

        end_time = datetime.datetime.now()
        elapsed_time = end_time - start_time
        print(f"\nScan completed at {end_time}. Elapsed time: {elapsed_time}.")

        if not open_ports:
            print(f"The host {target} is down.")
            retry = input("Do you want to try pinging the host? (y/n): ")
            if retry.lower() == 'y':
                ping_host(target)
        else:
            # Perform OS fingerprinting using python-nmap
            print("\nPerforming OS fingerprinting...")
            os_scan(target)

            # Check if there are open ports
            if open_ports:
                open_ports_str = ', '.join(map(str, open_ports))
                print(f"\nOpen ports detected: {open_ports_str}")

                # Prompt the user to open msfconsole
                open_msf = input("Do you want to open msfconsole? (y/n): ")
                if open_msf.lower() == 'y':
                    open_msfconsole()
            else:
                print(f"No open ports detected on {target}.")
    except TimeoutError as e:
        print(str(e))
        retry = input("Session timeout. Do you want to try again? (y/n): ")
        if retry.lower() == 'y':
            scan_ports(target, port_range, scan_type, speed, timeout)
        else:
            print("Exiting.")
    finally:
        signal.alarm(0)  # Disable the alarm

def scan_port(target, port, scan_type, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) if scan_type.lower() == 'tcp' else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            service = socket.getservbyport(port, scan_type.lower())  # Get service name
            print(f"Port {port}/{scan_type.upper()} is open. Service: {service}")
            open_ports.append(port)

            # Run service version detection in a separate thread
            threading.Thread(target=service_version_detection, args=(target, port, scan_type)).start()

    except Exception as e:
        print(f"Error scanning port {port}/{scan_type.upper()}: {e}")
    finally:
        sock.close()

def main():
    target = input("Enter the target IP address: ")
    port_range = input("Enter the port range to scan (e.g., 1-100): ")
    scan_type = input("Enter the type of ports to scan (tcp or udp): ")
    speed = input("Enter the scan speed (T1, T2, T3, T4, T5): ")
    timeout = int(input("Enter the session timeout in seconds: "))

    scan_ports(target, port_range, scan_type, speed, timeout)

if __name__ == "__main__":
    main()
