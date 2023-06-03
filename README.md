# 2IC80-Final-project

## Setup for SSL stripping

1. Enable IP forwarding on the machine
    - sudo vim /etc/sysctl.conf
    - Uncomment the line "net.ipv4.ip_forward = 1"
2. Set up packet forwarding using "iptables"
    - iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 1200
