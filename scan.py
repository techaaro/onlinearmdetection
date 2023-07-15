import os
import socket
import threading
import subprocess

ping_lock = threading.Lock()


def is_host_active(host, all_active_hosts):
    ping_resp = os.popen("ping -c 1 -t 2 " + host)
    for line in ping_resp.readlines():
        if line.count("ttl"):
            with ping_lock:
                all_active_hosts.append(host)
            break


nmap_lock = threading.Lock()


def find_os(host, all_os):
    scanv = subprocess.Popen(
        ["nmap", "-PR", "-O", str(host)], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()[0]
    scanList = scanv.split()
    print(str(scanList))
    with nmap_lock:
        if "printer" in scanList:
            all_os[host] = "Printer"
        elif "Linux" in scanList:
            all_os[host] = "Linux"
        elif "Windows" in scanList:
            all_os[host] = "Windows"
        elif "Apple" in scanList:
            all_os[host] = "Apple"
        elif "IOS" in scanList:
            all_os[host] = "IOS"
        else:
            all_os[host] = "Unknown"


tcp_scan_lock = threading.Lock()


def tcp_scan(host, all_open_ports):
    open_ports = list()
    for port in range(1, 10000):
        try:
            print("Looking at " + host + " for port" + str(port))
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_socket.connect((host, port))
            open_ports.append(port)
            tcp_socket.close()
        except Exception:
            pass
    with tcp_scan_lock:
        all_open_ports[host] = open_ports


# Find my IP address.
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip_address = s.getsockname()[0]
print("My IP address: " + my_ip_address)
s.close()

print("Starting scan...")
ip_split = my_ip_address.split(".")
network_prefix = ip_split[0] + "." + ip_split[1] + "." + ip_split[2]

# Find all hosts in the network using ping
all_active_hosts = list()
all_ping_threads = list()

for host_ip in range(2, 255):
    host_addr = network_prefix + "." + str(host_ip)
    ping_thread = threading.Thread(
        target=is_host_active,
        args=(
            host_addr,
            all_active_hosts,
        ),
    )
    ping_thread.start()
    all_ping_threads.append(ping_thread)
for ping_thread in all_ping_threads:
    ping_thread.join()

    # Find open ports in these active hosts
all_host_open_ports = {}
all_tcp_threads = list()

# Find OS device is running using NMAP
all_host_os = {}
all_nmap_threads = list()

for host in all_active_hosts:
    # TCP port scan
    tcp_thread = threading.Thread(
        target=tcp_scan,
        args=(
            host,
            all_host_open_ports,
        ),
    )
    tcp_thread.start()
    all_tcp_threads.append(tcp_thread)

    # OS detection
    nmap_thread = threading.Thread(
        target=find_os,
        args=(
            host,
            all_host_os,
        ),
    )
    nmap_thread.start()
    all_nmap_threads.append(nmap_thread)

for tcp_thread in all_tcp_threads:
    tcp_thread.join()


for nmap_thread in all_nmap_threads:
    nmap_thread.join()

print("Scan complete, Stats below:")
for host in all_active_hosts:
    print(
        "Address: {0} OS: {1} Open ports: {2}".format(
            host, all_host_os[host], all_host_open_ports[host]
        )
    )
