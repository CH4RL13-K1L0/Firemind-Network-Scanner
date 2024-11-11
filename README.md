Welcome to the FIREMIND NETWORK SCANNER

This is a very simple network scanner which sends a TCP-SYN request using the scapy python library to each available device on the network and sends back the IP of that device, allowing you to see a list of connected devices without netowrk admin privileges. This is done to avoid blocking ARP requests, despite ARP offering more device info than TCP.
