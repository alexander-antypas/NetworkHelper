# NetworkHelper
This is a .NET console application that provides various network and system diagnostic commands. 
It allows you to check port availability, network connectivity, DNS resolution, trace routes, query firewall status, and log all outputs to a file for later review.

Features

Interactive Commands: The application prompts for commands and arguments, running until you type exit.

Port Checks:
Check if a given IP/hostname and port is reachable.
Check if a given local port is in use and by which process.
Print all active TCP ports and their associated processes.
Print ports with their accessibility classification (Local Only, Private LAN, Internet).

Network Utilities:
ping: Test connectivity to a given host.
trace: Trace the route packets take to a given host.
dns: Perform DNS lookups for a given host.
firewall status: Display the current Windows firewall status.
Logging: Start logging all output to a timestamped text file on your Desktop.

Requirements
.NET SDK (6.0 or later recommended).
Windows OS is assumed for certain commands (tracert, netsh, nslookup), although the app can run on other platforms with adjustments.

Usage
Type a command and press Enter. Some commands prompt for additional input.

Commands:

help: Show a list of all available commands and their usage.
check ip: Check if a given IP/hostname and port is reachable.
Usage:
Type check ip, press Enter.
Enter the hostname/IP.
Enter the port number.
check port: Check if a given local port is in use and display the process using it.
Usage:
Type check port, press Enter.
Enter the local port number.
print ports: List all local TCP ports in use, their PID, and the associated process name.
print open: List all currently active TCP ports and classify them as Local Only, Private LAN, or Internet-accessible.
log: Start logging all console output to a file. A net_log_YYYYMMDD_HHMMSS.txt file will be created on your Desktop. Logging remains active until the application exits.
ping: Ping a given host to check its reachability.
Usage:
Type ping, press Enter.
Enter the host (e.g., google.com).
trace: Trace the route packets take to a given host.
Usage:
Type trace, press Enter.
Enter the host.
dns: Perform a DNS lookup for the specified host.
Usage:
Type dns, press Enter.
Enter the hostname.
firewall status: Display Windows firewall status for all profiles.
exit: Close the application.
Logging
To start logging, type log. A new log file will be created on your Desktop.
All subsequent output, including command inputs and results, will be written to the console and the log file.
Logging continues until you exit the application.

Known Limitations
Some commands rely on Windows-specific tools (tracert, nslookup, netsh) and may not function on non-Windows systems.
Identifying which process uses a port is done via netstat parsing; this could fail under certain conditions or require elevated privileges.
