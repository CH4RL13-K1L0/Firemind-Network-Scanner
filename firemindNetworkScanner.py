from asyncio import timeout

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1
import socket

def get_local_ip():
    """Get the local IP address of the device by connecting to an external host."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to an external host; doesn't actually send data
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip


def get_ip_range():
    """Determine the IP range based on the host IP"""
    local_ip = get_local_ip()
    network_prefix = '.'.join(local_ip.split('.')[:3])+'.024' # Assuming the subnet is /24, replace the last octet with 0/24
    return network_prefix

def get_hostname(ip):
    """Try to get the hostname of the device using reverse DNS lookup."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = None
    return hostname

def scan_network(ip_range, port=80):
    """Scan the network for connected devices"""
    base_ip = ip_range.split('/')[0]
    ip_prefix = '.'.join(base_ip.split('.')[:3]) + '.'

    print(f"Scanning network. Please wait...")
    print("Sending TCP SYN request...")

    devices = []
    for i in range(1,255):
        ip = f"{ip_prefix}{i}"
        packet = IP(dst=ip) / TCP(dport=port, flags="S") # creates SYN packet
        response = sr1(packet, timeout= 1, verbose = False) #send packet and await response

        if response and response.haslayer(TCP):
            # If we receive a SYN-ACK, it means the host is up and the port is open
            if response.getlayer(TCP).flags == 0x12: # 0x12 is the SYN-ACK flag
                print(f"Device found: {ip}")
                devices.append({'ip': ip, 'port': port})

                sr1(IP(dst=ip)/TCP(dport= port, flags="R"), timeout = 1, verbose = False)


    return devices

def main():
        ip_range = get_ip_range()
        devices = scan_network(ip_range)

        if devices:
            print("Device(s) found on network:")
            print("IP Address\t\tOpen port")
            print("-" * 40)
            for device in devices:
                print(f"{device.get('ip', 'N/A')}\t{device.get('port', 'N/A')}")
        else:
            print("No devices found on network, check connection and try again.")

if __name__ == "__main__":
    main()

