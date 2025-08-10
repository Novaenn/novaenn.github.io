+++
draft = false
authors = ["Samuele Bella"]
title = "WHY2025 CTF - Scan Me"
description = "WHY2025 CTF Scan Me"
date = "2025-08-09"
tags = [
    "python",
    "network",
    "ctf",
    "nmap",
    "nc",
]
categories = [
    "ctf",
]
series = ["WHY2025 CTF"]
+++

*"Last security audit reported that the system **scanme.ctf.zone** had a lot of open ports. We tried to close them, could you check if we still have open ports?"*

This is an easy Network challenge from the WHY2025 CTF I participated in.
The challenge's description clearly hints us at performing an nmap scan of `scanme.ctf.zone`.

By running `nmap -p- --open -T4 scanme.ctf.zone` we can perform a quick port scan that checks every possible TCP port on the host `scanme.ctf.zone` and only displays the ports that are currently open:
- *-p-*: This flag tells Nmap to scan all 65,535 TCP ports on the target host. By default, Nmap only scans the 1000 most common ports (I always make the mistake of not checking every port lol). The hyphen (`-`) without a specific port number is a shorthand for the entire port range.
- *--open*: This flag filters the results to only show ports that are in the "open" state. This hides ports that are "closed" or "filtered," which are not relevant for this challenge.    
- *-T4*: This sets the timing template to level 4, which is "Aggressive." This makes the scan faster by increasing the parallelization of probes and reducing the timeouts. While it's faster, it can also be more easily detected by firewalls or intrusion detection systems. However, this is a CTF challenge, so we don't care about that.

After waiting for a while, this is the result:
``` bash
~
❯ nmap -p- --open -T4 scanme.ctf.zone
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 09:35 CEST
Nmap scan report for scanme.ctf.zone (52.211.134.167)
Host is up (0.048s latency).
rDNS record for 52.211.134.167: ec2-52-211-134-167.eu-west-1.compute.amazonaws.com
Not shown: 65489 closed tcp ports (conn-refused), 7 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
2454/tcp  open  indx-dds
3871/tcp  open  avocent-adsap
7293/tcp  open  unknown
10962/tcp open  unknown
15160/tcp open  unknown
17983/tcp open  unknown
18395/tcp open  unknown
18728/tcp open  unknown
19185/tcp open  unknown
20447/tcp open  unknown
22258/tcp open  unknown
23990/tcp open  unknown
24196/tcp open  unknown
25161/tcp open  unknown
26525/tcp open  unknown
29115/tcp open  unknown
29172/tcp open  unknown
29762/tcp open  unknown
35486/tcp open  unknown
35725/tcp open  unknown
35943/tcp open  unknown
36650/tcp open  unknown
37299/tcp open  unknown
38897/tcp open  unknown
39461/tcp open  unknown
39961/tcp open  unknown
40632/tcp open  unknown
42747/tcp open  unknown
44426/tcp open  unknown
46045/tcp open  unknown
55283/tcp open  unknown
55305/tcp open  unknown
57932/tcp open  unknown
57937/tcp open  unknown
59220/tcp open  unknown
63931/tcp open  unknown
64199/tcp open  unknown
64471/tcp open  unknown
65534/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.55 seconds
```

Wow, that's a lot of open ports. Let's try to see what these ports really are.
By running `nmap -sT -sV scanme.ctf.zone -p 2454,3871` we obtain something really interesting:
``` bash
~
❯ nmap -sT -sV scanme.ctf.zone -p 2454,3871
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 09:41 CEST
Nmap scan report for scanme.ctf.zone (52.211.134.167)
Host is up (0.046s latency).
rDNS record for 52.211.134.167: ec2-52-211-134-167.eu-west-1.compute.amazonaws.com

PORT     STATE SERVICE        VERSION
2454/tcp open  indx-dds?
3871/tcp open  avocent-adsap?
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2454-TCP:V=7.95%I=7%D=8/9%Time=6896FBB3%P=x86_64-pc-linux-gnu%r(NUL
SF:L,1,"f");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3871-TCP:V=7.95%I=7%D=8/9%Time=6896FBB3%P=x86_64-pc-linux-gnu%r(NUL
SF:L,1,"l");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3.30 seconds
```

We see that from the probe and response data of the nmap service fingerprint result, the services respond with a single character.
`r(NULL,1,"f");` for example, means that the response given to the nmap service that sent a NULL probe, is the character f.

If we try to connect with `nc scanme.ctf.zone 2454`:
``` bash
~ 
❯ nc scanme.ctf.zone 2454
f
```
We'll get that exact same response.

From the first two ports, we might guess that the flag is given by connecting to each open port and concatenating all the characters given as response. To simplify our lives, we can write a script that does the hard work for us:
```python
import socket

def get_flag():
    host = "scanme.ctf.zone"
    ports = [
        2454, 3871, 7293, 10962, 15160, 17983, 18395, 18728, 19185, 20447, 22258,
        23990, 24196, 25161, 26525, 29115, 29172, 29762, 35486, 35725, 35943,
        36650, 37299, 38897, 39461, 39961, 40632, 42747, 44426, 46045, 55283,
        55305, 57932, 57937, 59220, 63931, 64199, 64471, 65534
    ]
    
    flag = ""
    
    print(f"[-] Connecting to host: {host}")
    print(f"[-] Retrieving flag characters from {len(ports)} ports...")

    for port in ports:
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a timeout of 2 seconds for the connection attempt
            s.settimeout(2)
            # Connect to the server on the specified port
            s.connect((host, port))
            # Receive up to 1024 bytes of data
            response = s.recv(1024)
            # Decode the bytes into a string and add to our flag
            flag += response.decode('utf-8')
            s.close()
            # Print a dot for progress
            print(".", end="", flush=True)
        except (socket.timeout, ConnectionRefusedError) as e:
            print(f"\n[!] Error connecting to port {port}: {e}")
            continue
            
    print("\n[+] Flag found:", flag)

if __name__ == "__main__":
    get_flag()
```

This script essentially connects to every open port we found with nmap, gets the response, and adds it to the flag string.

If we run it with `python solve.py`:
``` bash
Desktop/WHY2025 CTF/ScanMe via 🐍 v3.13.3
❯ python solve.py
[-] Connecting to host: scanme.ctf.zone
[-] Retrieving flag characters from 39 ports...
.......................................
[+] Flag found: flag{a0e2ef459c1b593054af4e2bb0028650}Use the order of ports for the order of the flag!
``` 

There was also a hint that we missed, if we tried to connect to port 65534 we would have received:
```bash
Desktop/WHY2025 CTF/ScanMe via 🐍 v3.13.3 took 3s
❯ nc scanme.ctf.zone 65534
Use the order of ports for the order of the flag!
```

**flag{a0e2ef459c1b593054af4e2bb0028650}**