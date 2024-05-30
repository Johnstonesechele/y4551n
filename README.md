Title: y4ss1t - A Versatile Port Scanner

Description:
y4ss1t is a powerful and user-friendly port scanner written in Python. It allows you to scan a specified IP address for both TCP and UDP ports, with the ability to customize the number of ports to scan and the time limit for the scan. This tool is designed to be a comprehensive solution for network security professionals, system administrators, and anyone who needs to quickly and efficiently identify open ports on a target system.

Installation:
1. Ensure you have Python 3 installed on your system.
2. Clone the y4ss1t repository from GitHub:
   ```
   git clone https://github.com/your-username/y4ss1t.git
   ```
3. Navigate to the project directory:
   ```
   cd y4ss1t
   ```
4. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

Usage:
1. Run the port scanner:
   ```
   python y4ss1t.py
   ```
2. When prompted, enter the IP address you want to scan.
3. Select the type of ports you want to scan (TCP, UDP, or both).
4. Enter the number of ports you want to scan.
5. Specify the time limit (in seconds) for the scan.
6. The port scanner will start and display the results as it progresses.

Example usage:
```
$ python y4ss1t.py
Enter the IP address to scan: 192.168.1.100
Select the port type (1 for TCP, 2 for UDP, 3 for both): 3
Enter the number of ports to scan: 1000
Enter the time limit (in seconds): 60
Scanning 192.168.1.100 for 1000 ports (TCP and UDP) with a time limit of 60 seconds...
Scan started at: 2023-04-18 12:34:56
Open TCP ports: 22, 80, 443
Open UDP ports: 53, 123
Scan completed at: 2023-04-18 12:35:56
```
