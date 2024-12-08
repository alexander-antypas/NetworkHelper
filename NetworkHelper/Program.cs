using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.IO;

class Program
{
    private static bool _isLogging = false;
    private static StreamWriter _logWriter;

    static async Task Main(string[] args)
    {
        PrintHelp();

        string command;
        do
        {
            Console.Write("> ");
            command = Console.ReadLine()?.Trim().ToLower();

            switch (command)
            {
                case "help":
                    PrintHelp();
                    break;

                case "check ip":
                    await HandleCheckIpAsync();
                    break;

                case "check port":
                    HandleCheckPort();
                    break;

                case "print ports":
                    HandlePrintPorts();
                    break;

                case "print open":
                    HandlePrintOpenPorts();
                    break;

                case "log":
                    StartLogging();
                    break;

                case "ping":
                    HandlePing();
                    break;

                case "trace":
                    HandleTrace();
                    break;

                case "dns":
                    HandleDns();
                    break;

                case "firewall status":
                    HandleFirewallStatus();
                    break;

                case "exit":
                    LogWriteLine("Exiting application...");
                    break;

                default:
                    if (!string.IsNullOrEmpty(command) && command != "exit")
                    {
                        LogWriteLine("Unknown command. Type 'help' for a list of available commands.");
                    }
                    break;
            }

        } while (command != "exit");

        // Close the log if it's open
        if (_isLogging)
        {
            _logWriter.Dispose();
        }
    }

    static void PrintHelp()
    {
        LogWriteLine("Available commands:");
        LogWriteLine(" help            - Show this help message");
        LogWriteLine(" check ip        - Check if a given IP/hostname and port is reachable");
        LogWriteLine(" check port      - Check if a given local port is in use and by which process");
        LogWriteLine(" print ports     - List all local TCP ports in use and their owning processes");
        LogWriteLine(" print open      - List all listening ports categorized by accessibility (Local/LAN/Internet)");
        LogWriteLine(" log             - Start logging console output to a file on the Desktop");
        LogWriteLine(" ping            - Ping a given host to check connectivity");
        LogWriteLine(" trace           - Trace the route packets take to a given host");
        LogWriteLine(" dns             - Perform a DNS lookup for a given host");
        LogWriteLine(" firewall status - Display the current firewall status");
        LogWriteLine(" exit            - Close the application");
    }

    static async Task HandleCheckIpAsync()
    {
        LogWrite("Enter the IP/Hostname to check: ");
        string host = Console.ReadLine()?.Trim();

        LogWrite("Enter the port to check: ");
        string portInput = Console.ReadLine()?.Trim();
        if (!int.TryParse(portInput, out int port))
        {
            LogWriteLine("Invalid port number.");
            return;
        }

        bool reachable = await IsPortReachableAsync(host, port);
        if (reachable)
        {
            LogWriteLine($"Success: {host}:{port} is reachable.");
        }
        else
        {
            LogWriteLine($"Failed to connect to {host}:{port}.");
            LogWriteLine("This may indicate the remote host is offline, the port is closed, or a firewall is blocking it.");
        }
    }

    static void HandleCheckPort()
    {
        LogWrite("Enter the port to check locally: ");
        string portInput = Console.ReadLine()?.Trim();
        if (!int.TryParse(portInput, out int port))
        {
            LogWriteLine("Invalid port number.");
            return;
        }

        bool inUse = IsLocalPortInUse(port);
        if (!inUse)
        {
            LogWriteLine($"Port {port} is not in use locally.");
        }
        else
        {
            var pid = GetLocalPortPID(port);
            if (pid != null)
            {
                try
                {
                    var p = Process.GetProcessById(pid.Value);
                    LogWriteLine($"Port {port} is used by PID {pid.Value}: {p.ProcessName}");
                }
                catch
                {
                    LogWriteLine($"Port {port} is used by PID {pid.Value}, but process details not found.");
                }
            }
            else
            {
                LogWriteLine($"Port {port} is in use, but unable to find the associated process.");
            }
        }
    }

    static void HandlePrintPorts()
    {
        var portPidMap = GetAllActiveTcpPorts();
        if (portPidMap.Count == 0)
        {
            LogWriteLine("No active TCP ports found.");
            return;
        }

        LogWriteLine(string.Format("{0,-10}{1,-10}{2,-20}", "Port", "PID", "Process Name"));
        LogWriteLine(new string('-', 40));

        foreach (var kvp in portPidMap)
        {
            int port = kvp.Key;
            int pid = kvp.Value;
            string procName;
            try
            {
                var p = Process.GetProcessById(pid);
                procName = p.ProcessName;
            }
            catch
            {
                procName = "N/A";
            }
            LogWriteLine(string.Format("{0,-10}{1,-10}{2,-20}", port, pid, procName));
        }
    }

    static void HandlePrintOpenPorts()
    {
        var connections = GetAllActiveTcpConnections();
        if (connections.Count == 0)
        {
            LogWriteLine("No active TCP ports found.");
            return;
        }

        LogWriteLine(string.Format("{0,-15}{1,-10}{2,-10}{3,-25}{4,-20}", "Local Address", "Port", "PID", "Process Name", "Accessibility"));
        LogWriteLine(new string('-', 80));

        foreach (var conn in connections)
        {
            string category = ClassifyAddress(conn.LocalAddress);

            string procName;
            try
            {
                var p = Process.GetProcessById(conn.PID);
                procName = p.ProcessName;
            }
            catch
            {
                procName = "N/A";
            }

            LogWriteLine(string.Format("{0,-15}{1,-10}{2,-10}{3,-25}{4,-20}",
                conn.LocalAddress,
                conn.Port,
                conn.PID,
                procName,
                category));
        }
    }

    static void HandlePing()
    {
        LogWrite("Enter the host to ping: ");
        string host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host))
        {
            LogWriteLine("Invalid host.");
            return;
        }

        RunCommandAndLog("ping", host);
    }

    static void HandleTrace()
    {
        LogWrite("Enter the host to trace: ");
        string host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host))
        {
            LogWriteLine("Invalid host.");
            return;
        }

        // "tracert" is Windows-specific. On non-Windows, consider "traceroute"
        RunCommandAndLog("tracert", host);
    }

    static void HandleDns()
    {
        LogWrite("Enter the hostname to resolve (DNS): ");
        string host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host))
        {
            LogWriteLine("Invalid host.");
            return;
        }

        // nslookup <host>
        RunCommandAndLog("nslookup", host);
    }

    static void HandleFirewallStatus()
    {
        // Display Windows Firewall status (all profiles)
        // Command: netsh advfirewall show allprofiles
        RunCommandAndLog("netsh", "advfirewall show allprofiles");
    }

    static void StartLogging()
    {
        if (_isLogging)
        {
            LogWriteLine("Logging is already active.");
            return;
        }

        string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string fileName = "net_log_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt";
        string fullPath = Path.Combine(desktopPath, fileName);

        try
        {
            _logWriter = new StreamWriter(fullPath, false);
            _logWriter.AutoFlush = true;
            _isLogging = true;
            Console.WriteLine($"Logging started: {fullPath}");
            _logWriter.WriteLine($"Logging started: {fullPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to start logging: " + ex.Message);
        }
    }

    static void LogWriteLine(string message)
    {
        Console.WriteLine(message);
        if (_isLogging)
        {
            _logWriter.WriteLine(message);
        }
    }

    static void LogWrite(string message)
    {
        Console.Write(message);
        if (_isLogging)
        {
            _logWriter.Write(message);
        }
    }

    static string ClassifyAddress(string ip)
    {
        if (ip == "127.0.0.1" || ip == "::1")
            return "Local Only";

        if (IsPrivateIP(ip))
            return "Private LAN";

        if (ip == "0.0.0.0")
            return "Internet (All Interfaces)";

        if (IsIPv4(ip))
            return "Public/Internet";

        return "Public/Internet"; // IPv6 default assumption
    }

    static bool IsPrivateIP(string ip)
    {
        if (!IsIPv4(ip)) return false;
        var parts = ip.Split('.');
        if (parts.Length == 4 &&
            int.TryParse(parts[0], out int p0) &&
            int.TryParse(parts[1], out int p1))
        {
            if (p0 == 10) return true;
            if (p0 == 192 && p1 == 168) return true;
            if (p0 == 172 && p1 >= 16 && p1 <= 31) return true;
        }
        return false;
    }

    static bool IsIPv4(string ip)
    {
        var parts = ip.Split('.');
        if (parts.Length != 4) return false;
        foreach (var part in parts)
        {
            if (!int.TryParse(part, out int val) || val < 0 || val > 255)
                return false;
        }
        return true;
    }

    static async Task<bool> IsPortReachableAsync(string host, int port, int timeoutMs = 3000)
    {
        try
        {
            using (var client = new TcpClient())
            {
                var connectTask = client.ConnectAsync(host, port);
                if (await Task.WhenAny(connectTask, Task.Delay(timeoutMs)) == connectTask && client.Connected)
                {
                    return true;
                }
            }
        }
        catch { }
        return false;
    }

    static bool IsLocalPortInUse(int port)
    {
        var ipProps = IPGlobalProperties.GetIPGlobalProperties();
        var tcpListeners = ipProps.GetActiveTcpListeners();
        return tcpListeners.Any(l => l.Port == port);
    }

    static int? GetLocalPortPID(int port)
    {
        var all = GetAllActiveTcpPorts();
        if (all.TryGetValue(port, out int pid))
        {
            return pid;
        }
        return null;
    }

    static System.Collections.Generic.Dictionary<int, int> GetAllActiveTcpPorts()
    {
        var result = new System.Collections.Generic.Dictionary<int, int>();
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-ano",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            using (var process = Process.Start(startInfo))
            {
                string output = process.StandardOutput.ReadToEnd();
                var lines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in lines)
                {
                    if (line.StartsWith("  TCP") || line.StartsWith("  UDP"))
                    {
                        var parts = line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 5)
                        {
                            string localAddress = parts[1];
                            string pidString = parts[parts.Length - 1];

                            var portMatch = Regex.Match(localAddress, @":(\d+)$");
                            if (portMatch.Success && int.TryParse(portMatch.Groups[1].Value, out int foundPort))
                            {
                                if (int.TryParse(pidString, out int pid))
                                {
                                    if (!result.ContainsKey(foundPort))
                                    {
                                        result.Add(foundPort, pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            // Ignore errors
        }

        return result;
    }

    class TcpConnectionInfo
    {
        public string LocalAddress { get; set; }
        public int Port { get; set; }
        public int PID { get; set; }
    }

    static System.Collections.Generic.List<TcpConnectionInfo> GetAllActiveTcpConnections()
    {
        var result = new System.Collections.Generic.List<TcpConnectionInfo>();

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-ano",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            using (var process = Process.Start(startInfo))
            {
                string output = process.StandardOutput.ReadToEnd();
                var lines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in lines)
                {
                    if (line.StartsWith("  TCP") || line.StartsWith("  UDP"))
                    {
                        var parts = line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 5)
                        {
                            string localAddress = parts[1];
                            string pidString = parts[parts.Length - 1];

                            var portMatch = Regex.Match(localAddress, @":(\d+)$");
                            if (portMatch.Success && int.TryParse(portMatch.Groups[1].Value, out int foundPort))
                            {
                                if (int.TryParse(pidString, out int pid))
                                {
                                    string ipPart = localAddress.Substring(0, localAddress.LastIndexOf(':'));
                                    result.Add(new TcpConnectionInfo
                                    {
                                        LocalAddress = ipPart,
                                        Port = foundPort,
                                        PID = pid
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            // Ignore errors
        }

        return result;
    }

    static void RunCommandAndLog(string command, string arguments)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (var process = Process.Start(startInfo))
            {
                string stdOut = process.StandardOutput.ReadToEnd();
                string stdErr = process.StandardError.ReadToEnd();

                if (!string.IsNullOrWhiteSpace(stdOut))
                    LogWriteLine(stdOut);
                if (!string.IsNullOrWhiteSpace(stdErr))
                    LogWriteLine(stdErr);
            }
        }
        catch (Exception ex)
        {
            LogWriteLine($"Error running {command}: {ex.Message}");
        }
    }
}
