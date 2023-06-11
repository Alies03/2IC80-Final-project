# 2IC80-Final-project

## Setup for SSL stripping

1. Enable IP forwarding on the machine
    - sudo vim /etc/sysctl.conf
    - Uncomment the line "net.ipv4.ip_forward = 1"
2. Set up packet forwarding using "iptables"
    - iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 1200

## Tool usage

Run our tool with the command `sudo python ARP.py`

Then you will see our textbased interface where you can select a silent mode or a verbose mode.

```
Please select the attack mode:
type "1" for silent mode
type "2" for verbose mode
```

The silent mode doesn output anything while the verbose mode gives updates on the progress.

 After that you can select the type of attack you want to execute. 

```
Please select the desired attack:
type "1" for ARP Poisoning
type "2" for DNS Spoofing
type "3" for SSL Stripping
type "4" to exit
```

While in an attack, you can stop the attack with a keyboard interrupt (press control-C). Then you are back in the attack selection menu and can select a different attack. If you press control-C in the attack selection menu, you also exit the program.


