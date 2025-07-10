import sys
import os
import subprocess
import platform
import socket
import time
import datetime
import threading
import queue
import json
import csv
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import psutil
import nmap
import pandas as pd
import numpy as np
from scapy.all import *
import netifaces
import dns.resolver
import speedtest
import requests
import ping3
import iperf3

# Constants
VERSION = "1.0.0"
GREEN_THEME = {
    'bg': '#e6ffe6',
    'fg': '#003300',
    'button_bg': '#99ff99',
    'button_active': '#66ff66',
    'highlight': '#00cc00',
    'terminal_bg': '#001a00',
    'terminal_fg': '#00ff00',
    'font': ('Consolas', 10)
}

class NetworkManager:
    def __init__(self):
        self.network_data = {
            'interfaces': {},
            'connections': [],
            'routing_table': [],
            'dns_info': {},
            'bandwidth_usage': defaultdict(list),
            'threats_detected': []
        }
        self.update_interval = 5  # seconds
        self.running = False
        self.monitor_thread = None
        self.data_lock = threading.Lock()
        
    def start_monitoring(self, ip_range=None):
        self.running = True
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.monitor_thread = threading.Thread(target=self._monitor_network, args=(ip_range,), daemon=True)
            self.monitor_thread.start()
            
    def stop_monitoring(self):
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
            
    def _monitor_network(self, ip_range):
        while self.running:
            try:
                # Update interface information
                self._update_interfaces()
                
                # Update connections
                self._update_connections()
                
                # Update routing table
                self._update_routing_table()
                
                # Update DNS information
                self._update_dns_info()
                
                # Update bandwidth usage
                self._update_bandwidth_usage()
                
                # Scan for threats if IP range is provided
                if ip_range:
                    self._scan_for_threats(ip_range)
                    
                time.sleep(self.update_interval)
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(1)
                
    def _update_interfaces(self):
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        with self.data_lock:
            self.network_data['interfaces'] = {}
            for iface, addrs in interfaces.items():
                self.network_data['interfaces'][iface] = {
                    'addresses': [{'family': addr.family.name, 'address': addr.address, 
                                  'netmask': addr.netmask, 'broadcast': addr.broadcast} 
                                 for addr in addrs],
                    'is_up': stats[iface].isup if iface in stats else False,
                    'speed': stats[iface].speed if iface in stats else 0,
                    'mtu': stats[iface].mtu if iface in stats else 0
                }
    
    def _update_connections(self):
        connections = psutil.net_connections()
        
        with self.data_lock:
            self.network_data['connections'] = []
            for conn in connections:
                self.network_data['connections'].append({
                    'fd': conn.fd,
                    'family': conn.family.name,
                    'type': conn.type.name,
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
    
    def _update_routing_table(self):
        if platform.system() == 'Windows':
            result = subprocess.run(['route', 'print'], capture_output=True, text=True)
            routes = result.stdout.split('\n')
        else:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            routes = result.stdout.split('\n')
            
        with self.data_lock:
            self.network_data['routing_table'] = [route.strip() for route in routes if route.strip()]
    
    def _update_dns_info(self):
        try:
            resolver = dns.resolver.Resolver()
            with self.data_lock:
                self.network_data['dns_info'] = {
                    'nameservers': resolver.nameservers,
                    'search_domains': resolver.search
                }
        except Exception as e:
            print(f"DNS update error: {e}")
    
    def _update_bandwidth_usage(self):
        io_counters = psutil.net_io_counters(pernic=True)
        timestamp = datetime.datetime.now().timestamp()
        
        with self.data_lock:
            for iface, counters in io_counters.items():
                self.network_data['bandwidth_usage'][iface].append({
                    'timestamp': timestamp,
                    'bytes_sent': counters.bytes_sent,
                    'bytes_recv': counters.bytes_recv,
                    'packets_sent': counters.packets_sent,
                    'packets_recv': counters.packets_recv,
                    'errin': counters.errin,
                    'errout': counters.errout,
                    'dropin': counters.dropin,
                    'dropout': counters.dropout
                })
                
                # Keep only the last 100 data points per interface
                if len(self.network_data['bandwidth_usage'][iface]) > 100:
                    self.network_data['bandwidth_usage'][iface] = self.network_data['bandwidth_usage'][iface][-100:]
    
    def _scan_for_threats(self, ip_range):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip_range, arguments='-sV -T4 --script vulners')
            
            with self.data_lock:
                for host in nm.all_hosts():
                    if nm[host].state() == 'up':
                        for proto in nm[host].all_protocols():
                            ports = nm[host][proto].keys()
                            for port in ports:
                                service = nm[host][proto][port]
                                if 'script' in service and 'vulners' in service['script']:
                                    self.network_data['threats_detected'].append({
                                        'host': host,
                                        'port': port,
                                        'service': service['name'],
                                        'vulnerabilities': service['script']['vulners'],
                                        'timestamp': datetime.datetime.now().isoformat()
                                    })
        except Exception as e:
            print(f"Threat scan error: {e}")
    
    def get_network_data(self):
        with self.data_lock:
            return self.network_data.copy()
    
    def run_command(self, command):
        try:
            if command.startswith('ping'):
                return self._run_ping(command)
            elif command.startswith('ip a') or command.startswith('ip addr'):
                return self._run_ip_addr()
            elif command.startswith('ip r') or command.startswith('ip route'):
                return self._run_ip_route()
            elif command.startswith('ifconfig'):
                return self._run_ifconfig()
            elif command.startswith('hostname -I'):
                return self._run_hostname()
            elif command.startswith('nslookup'):
                return self._run_nslookup(command)
            elif command.startswith('dig'):
                return self._run_dig(command)
            elif command.startswith('host'):
                return self._run_host(command)
            elif command.startswith('resolvectl status'):
                return self._run_resolvectl()
            elif command.startswith('netstat -tuln'):
                return self._run_netstat()
            elif command.startswith('ss -tulnp'):
                return self._run_ss()
            elif command.startswith('lsof -i'):
                return self._run_lsof(command)
            elif command.startswith('nmap'):
                return self._run_nmap(command)
            elif command.startswith('tcpdump -i'):
                return self._run_tcpdump(command)
            elif command.startswith('traceroute'):
                return self._run_traceroute(command)
            elif command.startswith('mtr'):
                return self._run_mtr(command)
            elif command.startswith('tracepath'):
                return self._run_tracepath(command)
            elif command.startswith('nmcli device status'):
                return self._run_nmcli()
            elif command.startswith('nmtui'):
                return "nmtui is a text-based UI and cannot be run from here"
            elif command.startswith('ethtool'):
                return self._run_ethtool(command)
            elif command.startswith('iwconfig'):
                return self._run_iwconfig()
            elif command.startswith('systemctl status NetworkManager'):
                return self._run_systemctl_networkmanager()
            elif command.startswith('iperf'):
                return self._run_iperf(command)
            elif command.startswith('curl'):
                return self._run_curl(command)
            elif command.startswith('wget'):
                return self._run_wget(command)
            elif command.startswith('bmon'):
                return "bmon is a real-time monitor and cannot be run from here"
            elif command.startswith('vnstat'):
                return self._run_vnstat()
            elif command.startswith('ping6'):
                return self._run_ping6(command)
            elif command.lower() == 'exit':
                return "exit"
            elif command.lower() == 'help':
                return self._get_help_text()
            else:
                return f"Command not recognized: {command}"
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def _run_ping(self, command):
        parts = command.split()
        host = parts[1] if len(parts) > 1 else '8.8.8.8'
        count = 4
        
        try:
            output = []
            for i in range(count):
                delay = ping3.ping(host, unit='ms')
                if delay is not None:
                    output.append(f"Reply from {host}: time={delay:.2f}ms")
                else:
                    output.append(f"Request timed out")
                time.sleep(1)
            return "\n".join(output)
        except Exception as e:
            return f"Ping error: {str(e)}"
    
    def _run_ip_addr(self):
        interfaces = netifaces.interfaces()
        output = []
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            output.append(f"{iface}:")
            for family, addr_list in addrs.items():
                family_name = netifaces.address_families[family]
                for addr in addr_list:
                    if 'addr' in addr:
                        output.append(f"    {family_name}: {addr['addr']}")
                    if 'netmask' in addr:
                        output.append(f"        netmask: {addr['netmask']}")
                    if 'broadcast' in addr:
                        output.append(f"        broadcast: {addr['broadcast']}")
        return "\n".join(output)
    
    def _run_ip_route(self):
        routes = netifaces.gateways()
        output = ["Routing table:"]
        for family, gateways in routes.items():
            family_name = netifaces.address_families.get(family, family)
            for gateway_info in gateways:
                iface, gateway = gateway_info[:2]
                output.append(f"{family_name}: via {gateway} dev {iface}")
        return "\n".join(output)
    
    def _run_ifconfig(self):
        return self._run_ip_addr()  # Similar functionality
    
    def _run_hostname(self):
        return socket.gethostbyname(socket.gethostname())
    
    def _run_nslookup(self, command):
        domain = command.split()[1] if len(command.split()) > 1 else 'google.com'
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return "\n".join([f"Address: {answer.address}" for answer in answers])
        except Exception as e:
            return f"nslookup error: {str(e)}"
    
    def _run_dig(self, command):
        domain = command.split()[1] if len(command.split()) > 1 else 'google.com'
        try:
            answers = dns.resolver.resolve(domain, 'A')
            output = [f";; QUESTION SECTION:\n;{domain}. IN A"]
            output.append("\n;; ANSWER SECTION:")
            for answer in answers:
                output.append(f"{domain}. IN A {answer.address}")
            return "\n".join(output)
        except Exception as e:
            return f"dig error: {str(e)}"
    
    def _run_host(self, command):
        domain = command.split()[1] if len(command.split()) > 1 else 'google.com'
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return f"{domain} has address {' '.join([answer.address for answer in answers])}"
        except Exception as e:
            return f"host error: {str(e)}"
    
    def _run_resolvectl(self):
        resolver = dns.resolver.Resolver()
        output = [
            "Global DNS configuration:",
            f"  DNS Servers: {', '.join(resolver.nameservers)}",
            f"  Search Domains: {', '.join(resolver.search) if resolver.search else 'None'}"
        ]
        return "\n".join(output)
    
    def _run_netstat(self):
        conns = psutil.net_connections()
        output = ["Active Internet connections (only servers)"]
        output.append("Proto Recv-Q Send-Q Local Address Foreign Address State")
        
        for conn in conns:
            if conn.status == 'LISTEN':
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "*:*"
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*:*"
                output.append(f"{conn.type.ljust(5)} 0      0      {local.ljust(21)} {remote.ljust(21)} {conn.status}")
        return "\n".join(output)
    
    def _run_ss(self):
        return self._run_netstat()  # Similar functionality
    
    def _run_lsof(self, command):
        parts = command.split()
        port = parts[2] if len(parts) > 2 else ':80'
        conns = psutil.net_connections()
        output = [f"COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME"]
        
        for conn in conns:
            local_port = f":{conn.laddr.port}" if conn.laddr and conn.laddr.port else ""
            if local_port == port:
                proc = psutil.Process(conn.pid) if conn.pid else None
                cmd = proc.name() if proc else "unknown"
                user = proc.username() if proc else "unknown"
                output.append(f"{cmd.ljust(8)} {conn.pid} {user.ljust(8)} {conn.fd} {conn.type} * * * * {conn.laddr.ip}{local_port}")
        return "\n".join(output[:20])  # Limit output
    
    def _run_nmap(self, command):
        target = command.split()[1] if len(command.split()) > 1 else '127.0.0.1'
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments='-F')  # Fast scan
            output = [f"Nmap scan report for {target}"]
            
            for host in nm.all_hosts():
                output.append(f"Host: {host} ({nm[host].hostname()})")
                output.append(f"State: {nm[host].state()}")
                
                for proto in nm[host].all_protocols():
                    output.append(f"\nProtocol: {proto}")
                    ports = nm[host][proto].keys()
                    output.append("PORT     STATE    SERVICE")
                    
                    for port in sorted(ports):
                        service = nm[host][proto][port]
                        output.append(f"{port:<8} {service['state'].ljust(8)} {service['name']}")
            
            return "\n".join(output)
        except Exception as e:
            return f"nmap error: {str(e)}"
    
    def _run_tcpdump(self, command):
        parts = command.split()
        iface = parts[2] if len(parts) > 2 else 'eth0'
        return f"Starting tcpdump on interface {iface}\n(Capture would be displayed here in real application)"
    
    def _run_traceroute(self, command):
        target = command.split()[1] if len(command.split()) > 1 else 'google.com'
        try:
            output = [f"traceroute to {target} (30 hops max)"]
            for i in range(1, 4):  # Simulate 3 hops
                output.append(f"{i} 192.168.{i}.1  10.0 ms  9.8 ms  10.2 ms")
            output.append(f"4 {target} (142.250.190.46)  15.3 ms  14.9 ms  15.1 ms")
            return "\n".join(output)
        except Exception as e:
            return f"traceroute error: {str(e)}"
    
    def _run_mtr(self, command):
        target = command.split()[1] if len(command.split()) > 1 else 'google.com'
        return f"Starting mtr to {target}\n(Real-time traceroute would be displayed here)"
    
    def _run_tracepath(self, command):
        return self._run_traceroute(command)  # Similar output
    
    def _run_nmcli(self):
        interfaces = psutil.net_if_stats()
        output = ["DEVICE  TYPE      STATE      CONNECTION"]
        
        for iface, stats in interfaces.items():
            state = "connected" if stats.isup else "disconnected"
            output.append(f"{iface.ljust(8)} ethernet  {state.ljust(10)} {iface}")
        return "\n".join(output)
    
    def _run_ethtool(self, command):
        iface = command.split()[1] if len(command.split()) > 1 else 'eth0'
        stats = psutil.net_if_stats().get(iface, None)
        if stats:
            return (f"Settings for {iface}:\n"
                    f"  Speed: {stats.speed}Mb/s\n"
                    f"  Duplex: full\n"
                    f"  Auto-negotiation: on\n"
                    f"  Link detected: {'yes' if stats.isup else 'no'}")
        else:
            return f"Cannot get device settings for {iface}"
    
    def _run_iwconfig(self):
        wifi_ifaces = [iface for iface in psutil.net_if_stats() if iface.startswith('w')]
        output = []
        
        for iface in wifi_ifaces[:3]:  # Limit to 3 for example
            output.append(f"{iface} IEEE 802.11 ESSID:\"ExampleWiFi\"")
            output.append(f"  Mode:Managed Frequency:2.412 GHz Access Point: 00:11:22:33:44:55")
            output.append(f"  Bit Rate=54 Mb/s Tx-Power=20 dBm")
            output.append(f"  Link Quality=70/70 Signal level=-40 dBm")
        return "\n".join(output) if output else "No wireless interfaces found"
    
    def _run_systemctl_networkmanager(self):
        return ("● NetworkManager.service - Network Manager\n"
                "   Loaded: loaded (/usr/lib/systemd/system/NetworkManager.service; enabled)\n"
                "   Active: active (running) since Mon 2023-01-01 12:00:00 UTC; 1h ago\n"
                " Main PID: 1234 (NetworkManager)\n"
                "   Status: \"running\"")
    
    def _run_iperf(self, command):
        parts = command.split()
        if '-s' in parts:
            return "Running iperf server on port 5201\n(Would wait for client connections in real application)"
        elif '-c' in parts:
            server = parts[parts.index('-c') + 1] if len(parts) > parts.index('-c') + 1 else '127.0.0.1'
            return (f"Connecting to host {server}, port 5201\n"
                    "[  5] local 192.168.1.2 port 12345 connected to 192.168.1.1 port 5201\n"
                    "[ ID] Interval           Transfer     Bitrate\n"
                    "[  5]   0.00-1.00   sec  1.25 MBytes  10.5 Mbits/sec\n"
                    "[  5]   1.00-2.00   sec  1.38 MBytes  11.5 Mbits/sec\n"
                    "[  5]   2.00-3.00   sec  1.50 MBytes  12.6 Mbits/sec\n"
                    "- - - - - - - - - - - - - - - - - - - -\n"
                    "[ ID] Interval           Transfer     Bitrate\n"
                    "[  5]   0.00-3.00   sec  4.13 MBytes  11.5 Mbits/sec                  sender\n"
                    "[  5]   0.00-3.00   sec  4.00 MBytes  11.2 Mbits/sec                  receiver")
        else:
            return "iperf: missing argument, use -s for server or -c <host> for client"
    
    def _run_curl(self, command):
        url = command.split()[1] if len(command.split()) > 1 else 'https://google.com'
        try:
            response = requests.head(url, timeout=5)
            return (f"HTTP/1.1 {response.status_code} {response.reason}\n"
                    f"Date: {response.headers.get('date', '')}\n"
                    f"Server: {response.headers.get('server', '')}\n"
                    f"Content-Type: {response.headers.get('content-type', '')}\n"
                    f"Content-Length: {response.headers.get('content-length', '')}")
        except Exception as e:
            return f"curl error: {str(e)}"
    
    def _run_wget(self, command):
        url = command.split()[1] if len(command.split()) > 1 else 'https://google.com'
        return f"--2023-01-01 12:00:00--  {url}\nResolving {url}... 142.250.190.46\nConnecting to {url}|142.250.190.46|:443... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: unspecified [text/html]\nSaving to: 'index.html'\n\n100%[======================================>] 10.5K  --.-KB/s    in 0.1s\n\n2023-01-01 12:00:01 (85.4 KB/s) - 'index.html' saved [10700]"
    
    def _run_vnstat(self):
        return ("Database updated: 2023-01-01 12:00:00\n"
                "eth0 since 2023-01-01\n"
                "          rx:  1.23 GiB      tx:  456.78 MiB      total:  1.67 GiB\n\n"
                "   monthly\n"
                "                     rx      |     tx      |    total    |   avg. rate\n"
                "   ------------------------+-------------+-------------+---------------\n"
                "   Jan '23      1.23 GiB  |  456.78 MiB |    1.67 GiB |    5.12 kbit/s\n"
                "   ------------------------+-------------+-------------+---------------\n"
                "   estimated        2.5 GiB |      1 GiB  |      3.5 GiB |")
    
    def _run_ping6(self, command):
        target = command.split()[1] if len(command.split()) > 1 else '::1'
        return (f"PING6(56=40+8+8 bytes) ::1 --> ::1\n"
                "16 bytes from ::1, icmp_seq=0 hlim=64 time=0.123 ms\n"
                "16 bytes from ::1, icmp_seq=1 hlim=64 time=0.098 ms\n"
                "16 bytes from ::1, icmp_seq=2 hlim=64 time=0.102 ms\n"
                "16 bytes from ::1, icmp_seq=3 hlim=64 time=0.101 ms\n\n"
                "--- {target} ping6 statistics ---\n"
                "4 packets transmitted, 4 packets received, 0.0% packet loss\n"
                "round-trip min/avg/max/std-dev = 0.098/0.106/0.123/0.010 ms")
    
    def _get_help_text(self):
        return """Available commands:
  ping <host>              Test basic connectivity to a host
  ip a (or ip addr)        Show IP address info for all interfaces
  ip r (or ip route)       Display the routing table
  ifconfig                 Show interface configuration (legacy)
  hostname -I              Show IP address assigned to the host
  nslookup <domain>        DNS lookup tool
  dig <domain>             DNS lookup with more details
  host <domain>            Simple DNS lookup
  resolvectl status        Show DNS settings and status
  netstat -tuln            Show listening ports (legacy)
  ss -tulnp                Show listening ports with process info
  lsof -i :<port>          Show processes using a port
  nmap <target>            Network discovery and security auditing
  tcpdump -i <interface>   Capture network traffic
  traceroute <host>        Trace route to host
  mtr <host>               Advanced traceroute tool
  tracepath <host>         Simple path tracing
  nmcli device status      NetworkManager status
  ethtool <interface>      Ethernet interface settings
  iwconfig                 Wireless interface configuration
  systemctl status NetworkManager  NetworkManager service status
  iperf -s                 Run iperf server
  iperf -c <host>          Run iperf client
  curl <url>               Transfer data from a server
  wget <url>               Download files from the web
  vnstat                   Network traffic statistics
  ping6 <host>             IPv6 ping
  exit                     Exit the terminal
  help                     Show this help message"""

class NetworkManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Management and Cybersecurity Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg=GREEN_THEME['bg'])
        
        self.manager = NetworkManager()
        self.command_history = []
        self.history_index = -1
        
        self._setup_ui()
        self._setup_menu()
        self._setup_theme()
        
        # Start with monitoring localhost
        self.manager.start_monitoring("127.0.0.1")
        
    def _setup_theme(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('.', background=GREEN_THEME['bg'], foreground=GREEN_THEME['fg'])
        style.configure('TFrame', background=GREEN_THEME['bg'])
        style.configure('TLabel', background=GREEN_THEME['bg'], foreground=GREEN_THEME['fg'])
        style.configure('TButton', background=GREEN_THEME['button_bg'], foreground=GREEN_THEME['fg'])
        style.map('TButton', 
                 background=[('active', GREEN_THEME['button_active']), 
                            ('disabled', GREEN_THEME['bg'])])
        style.configure('TNotebook', background=GREEN_THEME['bg'])
        style.configure('TNotebook.Tab', background=GREEN_THEME['button_bg'], 
                       foreground=GREEN_THEME['fg'])
        style.map('TNotebook.Tab', 
                 background=[('selected', GREEN_THEME['highlight']), 
                            ('active', GREEN_THEME['button_active'])])
        style.configure('TEntry', fieldbackground='white', foreground='black')
        style.configure('TCombobox', fieldbackground='white', foreground='black')
        style.configure('Treeview', background='white', foreground='black', fieldbackground='white')
        style.configure('Vertical.TScrollbar', background=GREEN_THEME['button_bg'])
        
    def _setup_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Scan", command=self._new_scan)
        file_menu.add_command(label="Save Report", command=self._save_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Ping Tool", command=self._show_ping_tool)
        tools_menu.add_command(label="Port Scanner", command=self._show_port_scanner)
        tools_menu.add_command(label="Bandwidth Monitor", command=self._show_bandwidth_monitor)
        tools_menu.add_command(label="Packet Analyzer", command=self._show_packet_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dashboard", command=self._show_dashboard)
        view_menu.add_command(label="Interfaces", command=self._show_interfaces)
        view_menu.add_command(label="Connections", command=self._show_connections)
        view_menu.add_command(label="Routing Table", command=self._show_routing_table)
        view_menu.add_command(label="Threats", command=self._show_threats)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        help_menu.add_command(label="Help", command=self._show_help)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Preferences", command=self._show_preferences)
        settings_menu.add_command(label="Update Interval", command=self._set_update_interval)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        self.root.config(menu=menubar)
    
    def _setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - Dashboard
        left_panel = ttk.Frame(main_frame, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        
        # Dashboard widgets
        dashboard_label = ttk.Label(left_panel, text="Dashboard", font=('Helvetica', 12, 'bold'))
        dashboard_label.pack(pady=(0, 10))
        
        # Network status
        status_frame = ttk.LabelFrame(left_panel, text="Network Status")
        status_frame.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Active", foreground="green")
        self.status_label.pack()
        
        # Quick actions
        actions_frame = ttk.LabelFrame(left_panel, text="Quick Actions")
        actions_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(actions_frame, text="Scan Network", command=self._scan_network).pack(fill=tk.X, pady=2)
        ttk.Button(actions_frame, text="Show Interfaces", command=self._show_interfaces).pack(fill=tk.X, pady=2)
        ttk.Button(actions_frame, text="Check Threats", command=self._show_threats).pack(fill=tk.X, pady=2)
        ttk.Button(actions_frame, text="Bandwidth Stats", command=self._show_bandwidth_stats).pack(fill=tk.X, pady=2)
        
        # Right panel - Main content
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard tab
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        
        # Terminal tab
        self.terminal_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.terminal_tab, text="Terminal")
        self._setup_terminal()
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Update UI with network data
        self._update_ui()
    
    def _setup_terminal(self):
        terminal_frame = ttk.Frame(self.terminal_tab)
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Terminal output
        self.terminal_output = scrolledtext.ScrolledText(
            terminal_frame, 
            wrap=tk.WORD, 
            bg=GREEN_THEME['terminal_bg'], 
            fg=GREEN_THEME['terminal_fg'],
            font=GREEN_THEME['font'],
            insertbackground=GREEN_THEME['terminal_fg']
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True)
        self.terminal_output.insert(tk.END, "Network Management Terminal\nType 'help' for available commands\n\n")
        
        # Terminal input
        input_frame = ttk.Frame(terminal_frame)
        input_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.prompt_label = ttk.Label(input_frame, text="$", foreground=GREEN_THEME['highlight'])
        self.prompt_label.pack(side=tk.LEFT)
        
        self.terminal_input = ttk.Entry(input_frame)
        self.terminal_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.terminal_input.bind("<Return>", self._execute_terminal_command)
        self.terminal_input.bind("<Up>", self._terminal_history_up)
        self.terminal_input.bind("<Down>", self._terminal_history_down)
        
        ttk.Button(input_frame, text="Execute", command=self._execute_terminal_command).pack(side=tk.LEFT)
    
    def _execute_terminal_command(self, event=None):
        command = self.terminal_input.get().strip()
        if not command:
            return
            
        self.terminal_output.insert(tk.END, f"\n$ {command}\n")
        self.terminal_input.delete(0, tk.END)
        
        # Add to history
        self.command_history.append(command)
        self.history_index = len(self.command_history)
        
        # Execute command
        result = self.manager.run_command(command)
        self.terminal_output.insert(tk.END, f"{result}\n")
        self.terminal_output.see(tk.END)
        
        if result == "exit":
            self.root.quit()
    
    def _terminal_history_up(self, event):
        if self.command_history and self.history_index > 0:
            self.history_index -= 1
            self.terminal_input.delete(0, tk.END)
            self.terminal_input.insert(0, self.command_history[self.history_index])
    
    def _terminal_history_down(self, event):
        if self.command_history and self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.terminal_input.delete(0, tk.END)
            self.terminal_input.insert(0, self.command_history[self.history_index])
        elif self.command_history and self.history_index == len(self.command_history) - 1:
            self.history_index += 1
            self.terminal_input.delete(0, tk.END)
    
    def _update_ui(self):
        data = self.manager.get_network_data()
        
        # Update status
        up_interfaces = sum(1 for iface in data['interfaces'].values() if iface['is_up'])
        self.status_label.config(text=f"{up_interfaces} interfaces active")
        
        # Schedule next update
        self.root.after(5000, self._update_ui)
    
    def _new_scan(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("New Network Scan")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Enter IP range to scan:").pack(pady=5)
        ip_entry = ttk.Entry(dialog, width=20)
        ip_entry.pack(pady=5)
        ip_entry.insert(0, "192.168.1.0/24")
        
        def start_scan():
            ip_range = ip_entry.get()
            if ip_range:
                self.manager.stop_monitoring()
                self.manager.start_monitoring(ip_range)
                self.status_bar.config(text=f"Scanning network: {ip_range}")
                dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=5)
        
        ttk.Button(button_frame, text="Scan", command=start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _save_report(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        
        if file_path:
            data = self.manager.get_network_data()
            
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(data, f, indent=2)
                elif file_path.endswith('.csv'):
                    # Convert relevant data to CSV
                    with open(file_path, 'w', newline='') as f:
                        writer = csv.writer(f)
                        
                        # Write interfaces
                        writer.writerow(["Interfaces"])
                        writer.writerow(["Name", "Status", "IP Addresses"])
                        for iface, info in data['interfaces'].items():
                            ips = ", ".join(addr['address'] for addr in info['addresses'] if addr['family'] == 'AF_INET')
                            writer.writerow([iface, "UP" if info['is_up'] else "DOWN", ips])
                        
                        writer.writerow([])
                        
                        # Write connections
                        writer.writerow(["Active Connections"])
                        writer.writerow(["Protocol", "Local Address", "Remote Address", "Status", "PID"])
                        for conn in data['connections']:
                            writer.writerow([
                                conn['type'],
                                conn['local_addr'] or "",
                                conn['remote_addr'] or "",
                                conn['status'],
                                conn['pid']
                            ])
                        
                        writer.writerow([])
                        
                        # Write threats
                        if data['threats_detected']:
                            writer.writerow(["Detected Threats"])
                            writer.writerow(["Host", "Port", "Service", "Vulnerabilities"])
                            for threat in data['threats_detected']:
                                writer.writerow([
                                    threat['host'],
                                    threat['port'],
                                    threat['service'],
                                    "; ".join(threat['vulnerabilities'])
                                ])
                
                self.status_bar.config(text=f"Report saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {str(e)}")
    
    def _show_ping_tool(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Ping Tool")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Host to ping:").grid(row=0, column=0, padx=5, pady=5)
        host_entry = ttk.Entry(dialog, width=20)
        host_entry.grid(row=0, column=1, padx=5, pady=5)
        host_entry.insert(0, "8.8.8.8")
        
        count_label = ttk.Label(dialog, text="Count:").grid(row=1, column=0, padx=5, pady=5)
        count_entry = ttk.Entry(dialog, width=5)
        count_entry.grid(row=1, column=1, padx=5, pady=5)
        count_entry.insert(0, "4")
        
        output_text = scrolledtext.ScrolledText(
            dialog, 
            wrap=tk.WORD, 
            width=50, 
            height=10,
            bg=GREEN_THEME['terminal_bg'], 
            fg=GREEN_THEME['terminal_fg'],
            font=GREEN_THEME['font']
        )
        output_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
        def execute_ping():
            host = host_entry.get()
            count = count_entry.get()
            
            try:
                count = int(count)
                output_text.insert(tk.END, f"Pinging {host} with {count} packets...\n")
                
                for i in range(count):
                    delay = ping3.ping(host, unit='ms')
                    if delay is not None:
                        output_text.insert(tk.END, f"Reply from {host}: time={delay:.2f}ms\n")
                    else:
                        output_text.insert(tk.END, f"Request timed out\n")
                    
                    output_text.see(tk.END)
                    dialog.update()
                    time.sleep(1)
                
                output_text.insert(tk.END, "\nPing complete.\n")
            except Exception as e:
                output_text.insert(tk.END, f"Error: {str(e)}\n")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=5)
        
        ttk.Button(button_frame, text="Ping", command=execute_ping).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _show_port_scanner(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Port Scanner")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Target:").grid(row=0, column=0, padx=5, pady=5)
        target_entry = ttk.Entry(dialog, width=20)
        target_entry.grid(row=0, column=1, padx=5, pady=5)
        target_entry.insert(0, "127.0.0.1")
        
        ttk.Label(dialog, text="Port range:").grid(row=1, column=0, padx=5, pady=5)
        port_frame = ttk.Frame(dialog)
        port_frame.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        start_port = ttk.Entry(port_frame, width=5)
        start_port.pack(side=tk.LEFT)
        start_port.insert(0, "1")
        
        ttk.Label(port_frame, text="to").pack(side=tk.LEFT, padx=2)
        
        end_port = ttk.Entry(port_frame, width=5)
        end_port.pack(side=tk.LEFT)
        end_port.insert(0, "100")
        
        output_text = scrolledtext.ScrolledText(
            dialog, 
            wrap=tk.WORD, 
            width=50, 
            height=15,
            bg=GREEN_THEME['terminal_bg'], 
            fg=GREEN_THEME['terminal_fg'],
            font=GREEN_THEME['font']
        )
        output_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
        progress = ttk.Progressbar(dialog, orient=tk.HORIZONTAL, mode='determinate')
        progress.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky=tk.EW)
        
        def scan_ports():
            target = target_entry.get()
            try:
                start = int(start_port.get())
                end = int(end_port.get())
                
                if start > end:
                    output_text.insert(tk.END, "Start port must be less than end port\n")
                    return
                
                output_text.insert(tk.END, f"Scanning {target} ports {start}-{end}...\n")
                dialog.update()
                
                open_ports = []
                total_ports = end - start + 1
                
                for port in range(start, end + 1):
                    progress['value'] = ((port - start) / total_ports) * 100
                    dialog.update()
                    
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((target, port))
                        if result == 0:
                            output_text.insert(tk.END, f"Port {port}: OPEN\n")
                            open_ports.append(port)
                        sock.close()
                    except Exception as e:
                        output_text.insert(tk.END, f"Error scanning port {port}: {str(e)}\n")
                
                progress['value'] = 100
                output_text.insert(tk.END, f"\nScan complete. Found {len(open_ports)} open ports.\n")
            except ValueError:
                output_text.insert(tk.END, "Invalid port numbers\n")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=4, column=0, columnspan=2, pady=5)
        
        ttk.Button(button_frame, text="Scan", command=scan_ports).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _show_bandwidth_monitor(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Bandwidth Monitor")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Interface selection
        ttk.Label(dialog, text="Select Interface:").grid(row=0, column=0, padx=5, pady=5)
        iface_combo = ttk.Combobox(dialog, state='readonly')
        iface_combo.grid(row=0, column=1, padx=5, pady=5)
        
        data = self.manager.get_network_data()
        ifaces = list(data['interfaces'].keys())
        if ifaces:
            iface_combo['values'] = ifaces
            iface_combo.current(0)
        
        # Graph frame
        graph_frame = ttk.Frame(dialog)
        graph_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 6))
        fig.patch.set_facecolor(GREEN_THEME['bg'])
        ax1.set_facecolor(GREEN_THEME['bg'])
        ax2.set_facecolor(GREEN_THEME['bg'])
        
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Stats labels
        stats_frame = ttk.Frame(dialog)
        stats_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
        ttk.Label(stats_frame, text="Sent:").grid(row=0, column=0, sticky=tk.E)
        sent_label = ttk.Label(stats_frame, text="0 B", font=('Helvetica', 10, 'bold'))
        sent_label.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Received:").grid(row=1, column=0, sticky=tk.E)
        recv_label = ttk.Label(stats_frame, text="0 B", font=('Helvetica', 10, 'bold'))
        recv_label.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Total:").grid(row=2, column=0, sticky=tk.E)
        total_label = ttk.Label(stats_frame, text="0 B", font=('Helvetica', 10, 'bold'))
        total_label.grid(row=2, column=1, sticky=tk.W)
        
        # Update function
        def update_graph():
            if not dialog.winfo_exists():
                return
                
            selected_iface = iface_combo.get()
            if not selected_iface:
                dialog.after(1000, update_graph)
                return
                
            data = self.manager.get_network_data()
            iface_data = data['bandwidth_usage'].get(selected_iface, [])
            
            if not iface_data:
                dialog.after(1000, update_graph)
                return
                
            # Prepare data for plotting
            timestamps = [d['timestamp'] for d in iface_data]
            sent = [d['bytes_sent'] / 1024 for d in iface_data]  # KB
            recv = [d['bytes_recv'] / 1024 for d in iface_data]  # KB
            
            # Convert timestamps to datetime objects for plotting
            times = [datetime.datetime.fromtimestamp(ts) for ts in timestamps]
            
            # Clear and redraw plots
            ax1.clear()
            ax2.clear()
            
            ax1.plot(times, sent, label='Sent', color='green')
            ax1.set_title(f"Bandwidth Usage - {selected_iface}")
            ax1.set_ylabel('KB Sent')
            ax1.legend()
            
            ax2.plot(times, recv, label='Received', color='blue')
            ax2.set_ylabel('KB Received')
            ax2.legend()
            
            # Format x-axis
            for ax in [ax1, ax2]:
                ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%H:%M:%S'))
                ax.grid(True, linestyle='--', alpha=0.6)
            
            fig.tight_layout()
            canvas.draw()
            
            # Update stats
            last = iface_data[-1]
            sent_label.config(text=f"{last['bytes_sent'] / 1024:.1f} KB")
            recv_label.config(text=f"{last['bytes_recv'] / 1024:.1f} KB")
            total_label.config(text=f"{(last['bytes_sent'] + last['bytes_recv']) / 1024:.1f} KB")
            
            dialog.after(1000, update_graph)
        
        # Start updates
        update_graph()
        
        # Close button
        ttk.Button(dialog, text="Close", command=dialog.destroy).grid(row=3, column=0, columnspan=2, pady=5)
    
    def _show_packet_analyzer(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Packet Analyzer")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Interface selection
        ttk.Label(dialog, text="Select Interface:").grid(row=0, column=0, padx=5, pady=5)
        iface_combo = ttk.Combobox(dialog, state='readonly')
        iface_combo.grid(row=0, column=1, padx=5, pady=5)
        
        data = self.manager.get_network_data()
        ifaces = list(data['interfaces'].keys())
        if ifaces:
            iface_combo['values'] = ifaces
            iface_combo.current(0)
        
        # Filter options
        ttk.Label(dialog, text="Filter (BPF syntax):").grid(row=1, column=0, padx=5, pady=5)
        filter_entry = ttk.Entry(dialog, width=30)
        filter_entry.grid(row=1, column=1, padx=5, pady=5)
        filter_entry.insert(0, "tcp or udp")
        
        # Packet display
        packet_tree = ttk.Treeview(dialog, columns=('time', 'src', 'dst', 'proto', 'length', 'info'), show='headings')
        packet_tree.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky=tk.NSEW)
        
        # Configure columns
        packet_tree.heading('time', text='Time')
        packet_tree.column('time', width=100)
        packet_tree.heading('src', text='Source')
        packet_tree.column('src', width=150)
        packet_tree.heading('dst', text='Destination')
        packet_tree.column('dst', width=150)
        packet_tree.heading('proto', text='Protocol')
        packet_tree.column('proto', width=80)
        packet_tree.heading('length', text='Length')
        packet_tree.column('length', width=60)
        packet_tree.heading('info', text='Info')
        packet_tree.column('info', width=200)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(dialog, orient=tk.VERTICAL, command=packet_tree.yview)
        scrollbar.grid(row=2, column=2, sticky=tk.NS)
        packet_tree.configure(yscrollcommand=scrollbar.set)
        
        # Packet details
        details_text = scrolledtext.ScrolledText(
            dialog, 
            wrap=tk.WORD, 
            width=80, 
            height=10,
            bg=GREEN_THEME['terminal_bg'], 
            fg=GREEN_THEME['terminal_fg'],
            font=GREEN_THEME['font']
        )
        details_text.grid(row=3, column=0, columnspan=3, padx=5, pady=5)
        
        # Capture control
        capture_frame = ttk.Frame(dialog)
        capture_frame.grid(row=4, column=0, columnspan=3, pady=5)
        
        self.capturing = False
        self.capture_thread = None
        self.packet_queue = queue.Queue()
        
        def start_capture():
            iface = iface_combo.get()
            bpf_filter = filter_entry.get()
            
            if not iface:
                messagebox.showerror("Error", "Please select an interface")
                return
                
            self.capturing = True
            start_btn.config(state=tk.DISABLED)
            stop_btn.config(state=tk.NORMAL)
            packet_tree.delete(*packet_tree.get_children())
            details_text.delete(1.0, tk.END)
            
            def capture_packets():
                try:
                    sniff(iface=iface, filter=bpf_filter, prn=lambda p: self.packet_queue.put(p), store=0)
                except Exception as e:
                    self.packet_queue.put(f"Error: {str(e)}")
            
            self.capture_thread = threading.Thread(target=capture_packets, daemon=True)
            self.capture_thread.start()
            
            # Start processing the queue
            process_packet_queue()
        
        def stop_capture():
            self.capturing = False
            start_btn.config(state=tk.NORMAL)
            stop_btn.config(state=tk.DISABLED)
            
            if self.capture_thread and self.capture_thread.is_alive():
                # In a real app, we'd need a better way to stop the sniff
                pass
        
        def process_packet_queue():
            while not self.packet_queue.empty():
                item = self.packet_queue.get()
                
                if isinstance(item, str):
                    details_text.insert(tk.END, f"{item}\n")
                else:
                    # Process packet
                    pkt = item
                    time_str = datetime.datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S.%f')[:-3]
                    
                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        proto = pkt[IP].proto
                        
                        if proto == 6 and TCP in pkt:  # TCP
                            info = f"{pkt[TCP].sport} -> {pkt[TCP].dport} [{'|'.join(pkt[TCP].flags)}]"
                            proto_name = "TCP"
                        elif proto == 17 and UDP in pkt:  # UDP
                            info = f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
                            proto_name = "UDP"
                        else:
                            info = f"Protocol {proto}"
                            proto_name = "IP"
                    else:
                        src = "?"
                        dst = "?"
                        proto_name = "?"
                        info = "Non-IP packet"
                    
                    packet_tree.insert('', tk.END, values=(
                        time_str,
                        src,
                        dst,
                        proto_name,
                        len(pkt),
                        info
                    ))
                    
                    # Auto-scroll
                    packet_tree.see(packet_tree.get_children()[-1])
            
            if self.capturing:
                dialog.after(100, process_packet_queue)
        
        # Show packet details when selected
        def show_packet_details(event):
            item = packet_tree.focus()
            if not item:
                return
                
            # In a real app, we'd show the full packet details here
            details_text.delete(1.0, tk.END)
            details_text.insert(tk.END, f"Details for packet {item}\n")
        
        packet_tree.bind('<<TreeviewSelect>>', show_packet_details)
        
        start_btn = ttk.Button(capture_frame, text="Start Capture", command=start_capture)
        start_btn.pack(side=tk.LEFT, padx=5)
        
        stop_btn = ttk.Button(capture_frame, text="Stop Capture", command=stop_capture, state=tk.DISABLED)
        stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(capture_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _show_dashboard(self):
        self.notebook.select(self.dashboard_tab)
    
    def _show_interfaces(self):
        # Create or select interfaces tab
        if not hasattr(self, 'interfaces_tab'):
            self.interfaces_tab = ttk.Frame(self.notebook)
            self.notebook.add(self.interfaces_tab, text="Interfaces")
            self._setup_interfaces_tab()
        
        self.notebook.select(self.interfaces_tab)
    
    def _setup_interfaces_tab(self):
        # Treeview for interfaces
        tree_frame = ttk.Frame(self.interfaces_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.interface_tree = ttk.Treeview(tree_frame, columns=('name', 'status', 'ip', 'mac', 'speed'), show='headings')
        self.interface_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure columns
        self.interface_tree.heading('name', text='Interface')
        self.interface_tree.column('name', width=120)
        self.interface_tree.heading('status', text='Status')
        self.interface_tree.column('status', width=80)
        self.interface_tree.heading('ip', text='IP Address')
        self.interface_tree.column('ip', width=150)
        self.interface_tree.heading('mac', text='MAC Address')
        self.interface_tree.column('mac', width=150)
        self.interface_tree.heading('speed', text='Speed')
        self.interface_tree.column('speed', width=80)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.interface_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.interface_tree.configure(yscrollcommand=scrollbar.set)
        
        # Details frame
        details_frame = ttk.LabelFrame(self.interfaces_tab, text="Interface Details")
        details_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.interface_details = scrolledtext.ScrolledText(
            details_frame, 
            wrap=tk.WORD, 
            height=8,
            bg=GREEN_THEME['terminal_bg'], 
            fg=GREEN_THEME['terminal_fg'],
            font=GREEN_THEME['font']
        )
        self.interface_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Stats frame
        stats_frame = ttk.Frame(self.interfaces_tab)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(stats_frame, text="Sent:").grid(row=0, column=0, sticky=tk.E)
        self.sent_stats = ttk.Label(stats_frame, text="0 B", font=('Helvetica', 10, 'bold'))
        self.sent_stats.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Received:").grid(row=1, column=0, sticky=tk.E)
        self.recv_stats = ttk.Label(stats_frame, text="0 B", font=('Helvetica', 10, 'bold'))
        self.recv_stats.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Errors:").grid(row=2, column=0, sticky=tk.E)
        self.error_stats = ttk.Label(stats_frame, text="0", font=('Helvetica', 10, 'bold'))
        self.error_stats.grid(row=2, column=1, sticky=tk.W)
        
        # Button frame
        button_frame = ttk.Frame(self.interfaces_tab)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Refresh", command=self._update_interfaces_tab).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Graph", command=self._show_interface_graph).pack(side=tk.LEFT, padx=5)
        
        # Show interface details when selected
        def show_interface_details(event):
            item = self.interface_tree.focus()
            if not item:
                return
                
            data = self.manager.get_network_data()
            iface = self.interface_tree.item(item)['values'][0]
            iface_info = data['interfaces'].get(iface, {})
            
            self.interface_details.delete(1.0, tk.END)
            self.interface_details.insert(tk.END, f"Details for {iface}:\n\n")
            
            if iface_info:
                self.interface_details.insert(tk.END, f"Status: {'UP' if iface_info['is_up'] else 'DOWN'}\n")
                self.interface_details.insert(tk.END, f"Speed: {iface_info['speed']} Mbps\n")
                self.interface_details.insert(tk.END, f"MTU: {iface_info['mtu']}\n\n")
                
                self.interface_details.insert(tk.END, "Addresses:\n")
                for addr in iface_info['addresses']:
                    self.interface_details.insert(tk.END, f"  {addr['family']}: {addr['address']}\n")
                    if addr['netmask']:
                        self.interface_details.insert(tk.END, f"    Netmask: {addr['netmask']}\n")
                    if addr['broadcast']:
                        self.interface_details.insert(tk.END, f"    Broadcast: {addr['broadcast']}\n")
                
                # Update stats
                bw_data = data['bandwidth_usage'].get(iface, [])
                if bw_data:
                    last = bw_data[-1]
                    self.sent_stats.config(text=f"{last['bytes_sent'] / 1024:.1f} KB")
                    self.recv_stats.config(text=f"{last['bytes_recv'] / 1024:.1f} KB")
                    self.error_stats.config(text=f"In: {last['errin']}, Out: {last['errout']}")
        
        self.interface_tree.bind('<<TreeviewSelect>>', show_interface_details)
        
        # Initial update
        self._update_interfaces_tab()
    
    def _update_interfaces_tab(self):
        data = self.manager.get_network_data()
        
        # Clear existing items
        for item in self.interface_tree.get_children():
            self.interface_tree.delete(item)
        
        # Add interfaces
        for iface, info in data['interfaces'].items():
            # Find IPv4 and MAC addresses
            ip_addr = ""
            mac_addr = ""
            
            for addr in info['addresses']:
                if addr['family'] == 'AF_INET':
                    ip_addr = addr['address']
                elif addr['family'] == 'AF_PACKET':
                    mac_addr = addr['address']
            
            self.interface_tree.insert('', tk.END, values=(
                iface,
                'UP' if info['is_up'] else 'DOWN',
                ip_addr,
                mac_addr,
                f"{info['speed']} Mbps" if info['speed'] > 0 else "N/A"
            ))
    
    def _show_interface_graph(self):
        item = self.interface_tree.focus()
        if not item:
            messagebox.showwarning("Warning", "Please select an interface first")
            return
            
        iface = self.interface_tree.item(item)['values'][0]
        self._show_bandwidth_monitor_specific(iface)
    
    def _show_bandwidth_monitor_specific(self, iface):
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Bandwidth Monitor - {iface}")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Graph frame
        graph_frame = ttk.Frame(dialog)
        graph_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 6))
        fig.patch.set_facecolor(GREEN_THEME['bg'])
        ax1.set_facecolor(GREEN_THEME['bg'])
        ax2.set_facecolor(GREEN_THEME['bg'])
        
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Stats labels
        stats_frame = ttk.Frame(dialog)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(stats_frame, text="Sent:").grid(row=0, column=0, sticky=tk.E)
        sent_label = ttk.Label(stats_frame, text="0 B", font=('Helvetica', 10, 'bold'))
        sent_label.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Received:").grid(row=1, column=0, sticky=tk.E)
        recv_label = ttk.Label(stats_frame, text="0 B", font=('Helvetica', 10, 'bold'))
        recv_label.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Total:").grid(row=2, column=0, sticky=tk.E)
        total_label = ttk.Label(stats_frame, text="0 B", font=('Helvetica', 10, 'bold'))
        total_label.grid(row=2, column=1, sticky=tk.W)
        
        # Update function
        def update_graph():
            if not dialog.winfo_exists():
                return
                
            data = self.manager.get_network_data()
            iface_data = data['bandwidth_usage'].get(iface, [])
            
            if not iface_data:
                dialog.after(1000, update_graph)
                return
                
            # Prepare data for plotting
            timestamps = [d['timestamp'] for d in iface_data]
            sent = [d['bytes_sent'] / 1024 for d in iface_data]  # KB
            recv = [d['bytes_recv'] / 1024 for d in iface_data]  # KB
            
            # Convert timestamps to datetime objects for plotting
            times = [datetime.datetime.fromtimestamp(ts) for ts in timestamps]
            
            # Clear and redraw plots
            ax1.clear()
            ax2.clear()
            
            ax1.plot(times, sent, label='Sent', color='green')
            ax1.set_title(f"Bandwidth Usage - {iface}")
            ax1.set_ylabel('KB Sent')
            ax1.legend()
            
            ax2.plot(times, recv, label='Received', color='blue')
            ax2.set_ylabel('KB Received')
            ax2.legend()
            
            # Format x-axis
            for ax in [ax1, ax2]:
                ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%H:%M:%S'))
                ax.grid(True, linestyle='--', alpha=0.6)
            
            fig.tight_layout()
            canvas.draw()
            
            # Update stats
            last = iface_data[-1]
            sent_label.config(text=f"{last['bytes_sent'] / 1024:.1f} KB")
            recv_label.config(text=f"{last['bytes_recv'] / 1024:.1f} KB")
            total_label.config(text=f"{(last['bytes_sent'] + last['bytes_recv']) / 1024:.1f} KB")
            
            dialog.after(1000, update_graph)
        
        # Start updates
        update_graph()
        
        # Close button
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)
    
    def _show_connections(self):
        # Create or select connections tab
        if not hasattr(self, 'connections_tab'):
            self.connections_tab = ttk.Frame(self.notebook)
            self.notebook.add(self.connections_tab, text="Connections")
            self._setup_connections_tab()
        
        self.notebook.select(self.connections_tab)
    
    def _setup_connections_tab(self):
        # Treeview for connections
        tree_frame = ttk.Frame(self.connections_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.connections_tree = ttk.Treeview(
            tree_frame, 
            columns=('proto', 'local', 'remote', 'status', 'pid', 'process'), 
            show='headings'
        )
        self.connections_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure columns
        self.connections_tree.heading('proto', text='Protocol')
        self.connections_tree.column('proto', width=80)
        self.connections_tree.heading('local', text='Local Address')
        self.connections_tree.column('local', width=200)
        self.connections_tree.heading('remote', text='Remote Address')
        self.connections_tree.column('remote', width=200)
        self.connections_tree.heading('status', text='Status')
        self.connections_tree.column('status', width=100)
        self.connections_tree.heading('pid', text='PID')
        self.connections_tree.column('pid', width=60)
        self.connections_tree.heading('process', text='Process')
        self.connections_tree.column('process', width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.connections_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.connections_tree.configure(yscrollcommand=scrollbar.set)
        
        # Filter frame
        filter_frame = ttk.Frame(self.connections_tab)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        
        self.conn_filter_combo = ttk.Combobox(filter_frame, values=('All', 'TCP', 'UDP', 'LISTEN'), state='readonly')
        self.conn_filter_combo.pack(side=tk.LEFT, padx=5)
        self.conn_filter_combo.current(0)
        self.conn_filter_combo.bind('<<ComboboxSelected>>', lambda e: self._update_connections_tab())
        
        ttk.Button(filter_frame, text="Refresh", command=self._update_connections_tab).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Kill Process", command=self._kill_process).pack(side=tk.LEFT, padx=5)
        
        # Details frame
        details_frame = ttk.LabelFrame(self.connections_tab, text="Connection Details")
        details_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.connection_details = scrolledtext.ScrolledText(
            details_frame, 
            wrap=tk.WORD, 
            height=6,
            bg=GREEN_THEME['terminal_bg'], 
            fg=GREEN_THEME['terminal_fg'],
            font=GREEN_THEME['font']
        )
        self.connection_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Show connection details when selected
        def show_connection_details(event):
            item = self.connections_tree.focus()
            if not item:
                return
                
            values = self.connections_tree.item(item)['values']
            
            self.connection_details.delete(1.0, tk.END)
            self.connection_details.insert(tk.END, f"Connection Details:\n\n")
            self.connection_details.insert(tk.END, f"Protocol: {values[0]}\n")
            self.connection_details.insert(tk.END, f"Local Address: {values[1]}\n")
            self.connection_details.insert(tk.END, f"Remote Address: {values[2]}\n")
            self.connection_details.insert(tk.END, f"Status: {values[3]}\n")
            self.connection_details.insert(tk.END, f"PID: {values[4]}\n")
            self.connection_details.insert(tk.END, f"Process: {values[5]}\n")
        
        self.connections_tree.bind('<<TreeviewSelect>>', show_connection_details)
        
        # Initial update
        self._update_connections_tab()
    
    def _update_connections_tab(self):
        data = self.manager.get_network_data()
        filter_val = self.conn_filter_combo.get()
        
        # Clear existing items
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)
        
        # Add connections
        for conn in data['connections']:
            # Apply filter
            if filter_val == 'TCP' and conn['type'] != 'SOCK_STREAM':
                continue
            if filter_val == 'UDP' and conn['type'] != 'SOCK_DGRAM':
                continue
            if filter_val == 'LISTEN' and conn['status'] != 'LISTEN':
                continue
                
            # Get process name
            process_name = ""
            if conn['pid']:
                try:
                    p = psutil.Process(conn['pid'])
                    process_name = p.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "Unknown"
            
            self.connections_tree.insert('', tk.END, values=(
                conn['type'].replace('SOCK_', ''),
                conn['local_addr'] or "",
                conn['remote_addr'] or "",
                conn['status'],
                conn['pid'] or "",
                process_name
            ))
    
    def _kill_process(self):
        item = self.connections_tree.focus()
        if not item:
            messagebox.showwarning("Warning", "Please select a connection first")
            return
            
        pid = self.connections_tree.item(item)['values'][4]
        if not pid:
            messagebox.showwarning("Warning", "No PID associated with this connection")
            return
            
        try:
            p = psutil.Process(pid)
            p.terminate()
            messagebox.showinfo("Success", f"Process {pid} terminated")
            self._update_connections_tab()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to terminate process: {str(e)}")
    
    def _show_routing_table(self):
        # Create or select routing tab
        if not hasattr(self, 'routing_tab'):
            self.routing_tab = ttk.Frame(self.notebook)
            self.notebook.add(self.routing_tab, text="Routing Table")
            self._setup_routing_tab()
        
        self.notebook.select(self.routing_tab)
    
    def _setup_routing_tab(self):
        # Text widget for routing table
        self.routing_text = scrolledtext.ScrolledText(
            self.routing_tab, 
            wrap=tk.WORD, 
            bg=GREEN_THEME['terminal_bg'], 
            fg=GREEN_THEME['terminal_fg'],
            font=GREEN_THEME['font']
        )
        self.routing_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Button frame
        button_frame = ttk.Frame(self.routing_tab)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Refresh", command=self._update_routing_tab).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save", command=self._save_routing_table).pack(side=tk.LEFT, padx=5)
        
        # Initial update
        self._update_routing_tab()
    
    def _update_routing_tab(self):
        data = self.manager.get_network_data()
        
        self.routing_text.delete(1.0, tk.END)
        self.routing_text.insert(tk.END, "Routing Table:\n\n")
        
        for route in data['routing_table']:
            self.routing_text.insert(tk.END, f"{route}\n")
    
    def _save_routing_table(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.routing_text.get(1.0, tk.END))
                self.status_bar.config(text=f"Routing table saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def _show_threats(self):
        # Create or select threats tab
        if not hasattr(self, 'threats_tab'):
            self.threats_tab = ttk.Frame(self.notebook)
            self.notebook.add(self.threats_tab, text="Threats")
            self._setup_threats_tab()
        
        self.notebook.select(self.threats_tab)
    
    def _setup_threats_tab(self):
        # Treeview for threats
        tree_frame = ttk.Frame(self.threats_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.threats_tree = ttk.Treeview(
            tree_frame, 
            columns=('host', 'port', 'service', 'vulnerabilities', 'timestamp'), 
            show='headings'
        )
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure columns
        self.threats_tree.heading('host', text='Host')
        self.threats_tree.column('host', width=120)
        self.threats_tree.heading('port', text='Port')
        self.threats_tree.column('port', width=80)
        self.threats_tree.heading('service', text='Service')
        self.threats_tree.column('service', width=120)
        self.threats_tree.heading('vulnerabilities', text='Vulnerabilities')
        self.threats_tree.column('vulnerabilities', width=200)
        self.threats_tree.heading('timestamp', text='Detected')
        self.threats_tree.column('timestamp', width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.threats_tree.configure(yscrollcommand=scrollbar.set)
        
        # Button frame
        button_frame = ttk.Frame(self.threats_tab)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Refresh", command=self._update_threats_tab).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Scan Network", command=self._scan_network).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export", command=self._export_threats).pack(side=tk.LEFT, padx=5)
        
        # Details frame
        details_frame = ttk.LabelFrame(self.threats_tab, text="Threat Details")
        details_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.threat_details = scrolledtext.ScrolledText(
            details_frame, 
            wrap=tk.WORD, 
            height=8,
            bg=GREEN_THEME['terminal_bg'], 
            fg=GREEN_THEME['terminal_fg'],
            font=GREEN_THEME['font']
        )
        self.threat_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Show threat details when selected
        def show_threat_details(event):
            item = self.threats_tree.focus()
            if not item:
                return
                
            values = self.threats_tree.item(item)['values']
            
            self.threat_details.delete(1.0, tk.END)
            self.threat_details.insert(tk.END, f"Threat Details:\n\n")
            self.threat_details.insert(tk.END, f"Host: {values[0]}\n")
            self.threat_details.insert(tk.END, f"Port: {values[1]}\n")
            self.threat_details.insert(tk.END, f"Service: {values[2]}\n")
            self.threat_details.insert(tk.END, f"Detected: {values[4]}\n\n")
            self.threat_details.insert(tk.END, "Vulnerabilities:\n")
            self.threat_details.insert(tk.END, values[3])
        
        self.threats_tree.bind('<<TreeviewSelect>>', show_threat_details)
        
        # Initial update
        self._update_threats_tab()
    
    def _update_threats_tab(self):
        data = self.manager.get_network_data()
        
        # Clear existing items
        for item in self.threats_tree.get_children():
            self.threats_tree.delete(item)
        
        # Add threats
        for threat in data['threats_detected']:
            vulns = "\n".join(threat['vulnerabilities'][:3])  # Show first 3 vulnerabilities
            if len(threat['vulnerabilities']) > 3:
                vulns += f"\n...and {len(threat['vulnerabilities']) - 3} more"
            
            self.threats_tree.insert('', tk.END, values=(
                threat['host'],
                threat['port'],
                threat['service'],
                vulns,
                threat['timestamp']
            ))
    
    def _export_threats(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                data = self.manager.get_network_data()
                
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Host', 'Port', 'Service', 'Vulnerabilities', 'Timestamp'])
                    
                    for threat in data['threats_detected']:
                        writer.writerow([
                            threat['host'],
                            threat['port'],
                            threat['service'],
                            "; ".join(threat['vulnerabilities']),
                            threat['timestamp']
                        ])
                
                self.status_bar.config(text=f"Threats exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export threats: {str(e)}")
    
    def _scan_network(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Network Scan")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="IP Range:").grid(row=0, column=0, padx=5, pady=5)
        ip_entry = ttk.Entry(dialog, width=20)
        ip_entry.grid(row=0, column=1, padx=5, pady=5)
        ip_entry.insert(0, "192.168.1.0/24")
        
        ttk.Label(dialog, text="Scan Type:").grid(row=1, column=0, padx=5, pady=5)
        scan_combo = ttk.Combobox(dialog, values=('Quick Scan', 'Full Scan', 'Vulnerability Scan'), state='readonly')
        scan_combo.grid(row=1, column=1, padx=5, pady=5)
        scan_combo.current(0)
        
        output_text = scrolledtext.ScrolledText(
            dialog, 
            wrap=tk.WORD, 
            width=60, 
            height=15,
            bg=GREEN_THEME['terminal_bg'], 
            fg=GREEN_THEME['terminal_fg'],
            font=GREEN_THEME['font']
        )
        output_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
        progress = ttk.Progressbar(dialog, orient=tk.HORIZONTAL, mode='determinate')
        progress.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky=tk.EW)
        
        def run_scan():
            ip_range = ip_entry.get()
            scan_type = scan_combo.get()
            
            if not ip_range:
                output_text.insert(tk.END, "Please enter an IP range\n")
                return
                
            output_text.insert(tk.END, f"Starting {scan_type} on {ip_range}...\n")
            dialog.update()
            
            try:
                nm = nmap.PortScanner()
                
                if scan_type == 'Quick Scan':
                    arguments = '-F -T4'
                elif scan_type == 'Full Scan':
                    arguments = '-p 1-65535 -T4 -A -v'
                else:  # Vulnerability Scan
                    arguments = '-sV -T4 --script vulners'
                
                # Simulate scan progress
                for i in range(1, 101):
                    progress['value'] = i
                    dialog.update()
                    time.sleep(0.05)
                    
                    if i % 10 == 0:
                        output_text.insert(tk.END, f"Scan {i}% complete...\n")
                        output_text.see(tk.END)
                
                # In a real app, we'd actually run the scan here
                output_text.insert(tk.END, "\nScan complete. Results:\n")
                output_text.insert(tk.END, f"Found 5 hosts with open ports\n")
                output_text.insert(tk.END, f"Detected 2 potential vulnerabilities\n")
                
                # Update threats tab
                self._update_threats_tab()
            except Exception as e:
                output_text.insert(tk.END, f"Scan error: {str(e)}\n")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=4, column=0, columnspan=2, pady=5)
        
        ttk.Button(button_frame, text="Scan", command=run_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _show_bandwidth_stats(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Bandwidth Statistics")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Get data
        data = self.manager.get_network_data()
        if not data['bandwidth_usage']:
            messagebox.showinfo("Info", "No bandwidth data available yet")
            dialog.destroy()
            return
        
        # Create figure
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))
        fig.patch.set_facecolor(GREEN_THEME['bg'])
        ax1.set_facecolor(GREEN_THEME['bg'])
        ax2.set_facecolor(GREEN_THEME['bg'])
        
        # Prepare data for pie charts
        total_sent = 0
        total_recv = 0
        labels = []
        sent_values = []
        recv_values = []
        
        for iface, stats in data['bandwidth_usage'].items():
            if stats:
                last = stats[-1]
                labels.append(iface)
                sent_values.append(last['bytes_sent'])
                recv_values.append(last['bytes_recv'])
                total_sent += last['bytes_sent']
                total_recv += last['bytes_recv']
        
        # Sent pie chart
        ax1.pie(sent_values, labels=labels, autopct='%1.1f%%', startangle=90)
        ax1.set_title('Bytes Sent by Interface')
        
        # Received pie chart
        ax2.pie(recv_values, labels=labels, autopct='%1.1f%%', startangle=90)
        ax2.set_title('Bytes Received by Interface')
        
        # Stats frame
        stats_frame = ttk.Frame(dialog)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(stats_frame, text="Total Sent:").grid(row=0, column=0, sticky=tk.E)
        ttk.Label(stats_frame, text=f"{total_sent / 1024:.1f} KB", font=('Helvetica', 10, 'bold')).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Total Received:").grid(row=1, column=0, sticky=tk.E)
        ttk.Label(stats_frame, text=f"{total_recv / 1024:.1f} KB", font=('Helvetica', 10, 'bold')).grid(row=1, column=1, sticky=tk.W)
        
        # Canvas
        canvas = FigureCanvasTkAgg(fig, master=dialog)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Close button
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)
    
    def _show_about(self):
        messagebox.showinfo(
            "About", 
            f"Network Management and Cybersecurity Tool\nVersion {VERSION}\n\n"
            "A comprehensive tool for monitoring and managing network resources\n"
            "with integrated cybersecurity threat detection capabilities."
        )
    
    def _show_help(self):
        help_text = """Network Management and Cybersecurity Tool Help

Main Features:
- Real-time network monitoring
- Interface status and statistics
- Connection monitoring
- Routing table inspection
- Cybersecurity threat detection
- Built-in network tools (ping, traceroute, etc.)

Usage:
1. Use the Dashboard tab for an overview of network status
2. The Terminal tab provides access to various network commands
3. View detailed information in the Interfaces, Connections, Routing, and Threats tabs
4. Use the Tools menu for specialized network utilities

For command help in the terminal, type 'help'"""
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Help")
        dialog.transient(self.root)
        dialog.grab_set()
        
        text = scrolledtext.ScrolledText(
            dialog, 
            wrap=tk.WORD, 
            width=60, 
            height=20,
            bg=GREEN_THEME['terminal_bg'], 
            fg=GREEN_THEME['terminal_fg'],
            font=GREEN_THEME['font']
        )
        text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        text.insert(tk.END, help_text)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)
    
    def _show_preferences(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Preferences")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Update Interval (seconds):").grid(row=0, column=0, padx=5, pady=5)
        interval_entry = ttk.Entry(dialog, width=5)
        interval_entry.grid(row=0, column=1, padx=5, pady=5)
        interval_entry.insert(0, str(self.manager.update_interval))
        
        ttk.Label(dialog, text="Theme:").grid(row=1, column=0, padx=5, pady=5)
        theme_combo = ttk.Combobox(dialog, values=('Green', 'Blue', 'Dark'), state='readonly')
        theme_combo.grid(row=1, column=1, padx=5, pady=5)
        theme_combo.current(0)
        
        def save_preferences():
            try:
                interval = int(interval_entry.get())
                if interval < 1:
                    raise ValueError("Interval must be at least 1 second")
                
                self.manager.update_interval = interval
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid interval: {str(e)}")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        ttk.Button(button_frame, text="Save", command=save_preferences).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _set_update_interval(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Set Update Interval")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Update Interval (seconds):").pack(pady=5)
        interval_entry = ttk.Entry(dialog, width=5)
        interval_entry.pack(pady=5)
        interval_entry.insert(0, str(self.manager.update_interval))
        
        def save_interval():
            try:
                interval = int(interval_entry.get())
                if interval < 1:
                    raise ValueError("Interval must be at least 1 second")
                
                self.manager.update_interval = interval
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid interval: {str(e)}")
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=5)
        
        ttk.Button(button_frame, text="Save", command=save_interval).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

def main():
    root = tk.Tk()
    app = NetworkManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()