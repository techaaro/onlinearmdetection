import socket
import threading
from scapy.all import srp, Ether, ARP
import nmap

ping_lock = threading.Lock()
nmap_lock = threading.Lock()
tcp_scan_lock = threading.Lock()


def is_host_active(network_prefix, host_ip, all_active_hosts):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        pdst=network_prefix + "." + str(host_ip)
    )
    result = srp(packet, timeout=2, verbose=0)[0]
    if result:
        with ping_lock:
            all_active_hosts.append(result[0][1].src)


def find_os(host, all_os):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments="-O")
    try:
        if "osclass" in nm[host]:
            best_os_guess = nm[host]["osclass"][0]["osfamily"]
            with nmap_lock:
                all_os[host] = best_os_guess
        else:
            with nmap_lock:
                all_os[host] = "Unknown"
    except KeyError:
        with nmap_lock:
            all_os[host] = "Unknown"


def tcp_scan(host, all_open_ports):
    open_ports = []
    for port in range(1, 10000):
        try:
            print("Looking at " + host + " for port " + str(port))
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

# Find all hosts in the network using Scapy
all_active_hosts = []
all_ping_threads = []
for host_ip in range(1, 255):
    ping_thread = threading.Thread(
        target=is_host_active, args=(network_prefix, host_ip, all_active_hosts)
    )
    ping_thread.start()
    all_ping_threads.append(ping_thread)
for thread in all_ping_threads:
    thread.join()
all_active_hosts.sort()

# Find open ports in these active hosts
all_host_open_ports = {}
all_tcp_threads = []
for host in all_active_hosts:
    tcp_thread = threading.Thread(target=tcp_scan, args=(host, all_host_open_ports))
    tcp_thread.start()
    all_tcp_threads.append(tcp_thread)
for thread in all_tcp_threads:
    thread.join()

# Find OS device is running using python-nmap
all_host_os = {}
all_nmap_threads = []
for host in all_active_hosts:
    nmap_thread = threading.Thread(target=find_os, args=(host, all_host_os))
    nmap_thread.start()
    all_nmap_threads.append(nmap_thread)
for thread in all_nmap_threads:
    thread.join()

print("Scan complete, Stats below:")
for host in all_active_hosts:
    os_info = all_host_os.get(host, "Unknown")
    open_ports = all_host_open_ports.get(host, [])
    print("Address: {0} OS: {1} Open ports: {2}".format(host, os_info, open_ports))
