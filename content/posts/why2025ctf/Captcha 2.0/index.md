+++
draft = false
authors = ["Samuele Bella"]
title = "WHY2025 CTF - Captcha 2.0"
description = "WHY2025 CTF Captcha 2.0"
date = "2025-08-09"
tags = [
    "python",
    "network",
    "ctf",
    "wireshark",
    "nc",
]
categories = [
    "ctf",
]
series = ["WHY2025 CTF"]
+++

*Someone hacked our MCH challenge Captcha, luckily we still have the network logs.*

Captcha 2.0 is a medium-difficulty Network challenge from the WHY2025 CTF I participated in August.

The .pcap file we are given appears to be an unencrypted HTTP session.
{{< figure src="images/Captcha.png" alt="Captcha 2.0" >}}

From this Wireshark view, we notice a `POST /login.php` which contains the login information that *3.73.196.44*	sent to *172.31.38.49*:
- user = test
- pass = test
- captcha = fry
15 packets lower, we see the response, an `HTTP/1.1 200 OK` which returns the following html page:
```html

<!DOCTYPE html>
<html>

<head>
  <meta charset="UTF-8" />

  <title>Futurama Lovers!</title>
  <link rel="stylesheet" href="style.css" />
</head>
<body id="home">

  <header>
    <div id="logo">Futurama Lovers!</div>
  </header>

  <section id="main" class="main">


<div id="box" class="box">
        <form action="login.php" method="post">
<div id="error">Error with captcha</div>
<p><label for="user">Username:</label> <input name="user" type="text" /></p><p><label for="pass">Password:</label> <input name="pass" type="password" /></p><div class="captcha"><h3>Captcha</h3><img src="data:image/png;base64,iVBORw0KGgoAAAA..."><p> <input name="captcha" type="text" placeholder="Name of Futurama Character"/></p></div>    <p class="submit"><input name="submit" type="submit" value="Login" /></p>
    </form>
        <p><label></label><strong>Demo Login: </strong>test/test</p>
</div>
<footer>
   &copy;3022 CTF Challenge
</footer>
</body>
</html>


```

We see an **Error with captcha** message, but let's look at the other connections.
Let's also use a display filter to hide all the TCP Packets:
`http.response == 200 or http.request.method == "POST"`
This shows us every packet that has an HTTP Response of 200 or an HTTP Request method of POST.
After filtering, we notice that packet 50 has a different input for the user form item:
{{< figure src="images/Blind SQLI-1.png" alt="Blind SQLi 1" >}}
This is a clear attempt at a **Blind SQLi Injection**, where the attacker is trying to extract information from the `SQLITE_MASTER` table, which contains metadata about the database schema. The `SUBSTR` and `LIMIT` clauses are used for blind SQL injection, where the attacker tries to guess the database content character by character.

Every subsequent POST Request tries to infer the name of the first table of the database, which is **userTable**.
Then, from packet 66738, the attacker tries to perform a Blind SQL Injection on the password column of userTable.

An interesting packet is 66910, the attacker tries `user = test' AND (SELECT SUBSTR(password,1,1)  FROM userTable LIMIT 0,1) = 'f` and the server responds with an HTTP 302 Found, before giving the HTTP 200 OK which shows a succesful login:
{{< figure src="images/Blind SQLI-2.png" alt="Blind SQLi 2" >}}

If we filter by `http.response == 302` we can see every HTTP 302 Found response, which helps us find the correct characters for every password position.
The flag might be the password itself, we just need to get all the succesful login attempts and concatenate the characters.

To extract these login attempts, we must first extract every packet with an HTTP 200 response that contains the succesful "Welcome user" message. 
This script leverages the scapy library to help us do exactly this:
```python
#!/usr/bin/env python3
import sys
import os
import zlib
from datetime import datetime
import logging

# Disable Scapy's default verbose logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    import brotli
    BROTLI_SUPPORT = True
except ImportError:
    BROTLI_SUPPORT = False

try:
    from scapy.all import rdpcap, TCP, Raw, IP
except ImportError:
    print("Scapy is not installed. Please run 'pip install scapy' to install it.")
    sys.exit(1)


# --- Configuration ---
OUTPUT_FILE = "captured_packets.txt"
CONTENT_TYPE_FILTER = "Content-Type: text/html"
WELCOME_MESSAGE_FILTER = "<p>Welcome user test'"


def process_packet(packet):
    """
    Inspects a single packet, handles decompression, and checks for content.
    Returns True if a matching packet is found and saved, otherwise False.
    """
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return False

    raw_load = packet[Raw].load

    try:
        header_end_index = raw_load.find(b'\r\n\r\n')
        if header_end_index == -1:
            return False  # Not a complete HTTP header in this packet

        headers_bytes = raw_load[:header_end_index]
        body_bytes = raw_load[header_end_index + 4:]
        headers_str = headers_bytes.decode('utf-8', errors='ignore').lower()

    except Exception:
        return False  # Packet data is not valid

    if CONTENT_TYPE_FILTER.lower() not in headers_str:
        return False

    decompressed_body = b''
    try:
        if 'content-encoding: gzip' in headers_str:
            # The `16 + zlib.MAX_WBITS` is a magic value to handle gzip headers
            decompressed_body = zlib.decompress(body_bytes, 16 + zlib.MAX_WBITS)
        elif 'content-encoding: deflate' in headers_str:
            decompressed_body = zlib.decompress(body_bytes)
        elif 'content-encoding: br' in headers_str:
            if BROTLI_SUPPORT:
                decompressed_body = brotli.decompress(body_bytes)
            else:
                return False  # Can't decompress, so we can't search
        else:
            decompressed_body = body_bytes  # No compression
    except Exception:
        # Decompression can fail on partial/corrupt streams
        return False

    # Search the decompressed payload
    final_payload_str = decompressed_body.decode('utf-8', errors='ignore')

    if WELCOME_MESSAGE_FILTER in final_payload_str:
        print(f"[+] Packet Found! Contains '{WELCOME_MESSAGE_FILTER}'. Saving to {OUTPUT_FILE}")
        save_packet(packet, decompressed_body)
        return True

    return False


def save_packet(packet, decompressed_body):
    """Saves packet details and its decompressed body to the output file."""
    with open(OUTPUT_FILE, 'a') as f:
        f.write("=" * 60 + "\n")
        f.write(f"Packet from pcap file, processed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        if packet.haslayer(IP):
            f.write(f"Source: {packet[IP].src}:{packet[TCP].sport}\n")
            f.write(f"Destination: {packet[IP].dst}:{packet[TCP].dport}\n")

        f.write("-" * 60 + "\n")
        f.write("--- DECOMPRESSED HTTP BODY ---\n\n")
        # Decode the bytes to a string, replacing errors to prevent crashes.
        f.write(decompressed_body.decode('utf-8', errors='replace'))
        f.write("\n\n--- END DECOMPRESSED BODY ---\n\n\n")


def main():
    """Main function to read a pcap file and process its packets."""
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    if not os.path.exists(pcap_file):
        print(f"[!] Error: File not found at '{pcap_file}'")
        sys.exit(1)

    if not BROTLI_SUPPORT:
        print("[!] Warning: 'brotli' library not found. Run 'pip install brotli' to handle Brotli compressed content.")

    print(f"[*] Reading packets from '{pcap_file}'...")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Scapy could not read the file. Error: {e}")
        sys.exit(1)

    total_packets = len(packets)
    found_count = 0
    print(f"[*] Analyzing {total_packets} packets...")

    for i, packet in enumerate(packets):
        if process_packet(packet):
            found_count += 1
        print(f"[*] Processed {i + 1}/{total_packets} packets...", end='\r')

    print("\n" + "=" * 40)
    print("[*] Analysis Complete.")
    print(f"[*] Matching packets found: {found_count}")
    if found_count > 0:
        print(f"[*] Details have been saved to '{OUTPUT_FILE}'")
    print("=" * 40)


if __name__ == "__main__":
    main()```

This script reads every packet, decompresses with GZIP the HTTP traffic, and checks if it contains the succesful login string. If it does, the packet is saved inside `captured_packets.txt`.

By analizing the .txt file, we can see that the first 5 characters of the password are indeed **flag{** so our initial intuition was correct.

Now, we could extract the flag manually, or, we could spend the next 20 minutes of our lives to build a regex that extracts each flag character from the packets:
```python
#!/usr/bin/env python3
import re
import sys

def extract_flag(file_content):
    extracted_data = {}

    # This more specific regex looks for the exact HTML structure and extracts the
    # key pieces of information from the successful SQL injection queries.
    # - Group 1 (column): `sql` or `password`
    # - Group 2 (position): The character's position (e.g., '1', '38')
    # - Group 3 (character): The successfully guessed character (e.g., 'C', '}')
    pattern = re.compile(
        r"<p>Welcome user test' AND \(SELECT SUBSTR\((.*?),\s*(\d+),1\)\s*FROM\s*(?:SQLITE_MASTER|userTable).*? = '(.)\."
    )

    for match in pattern.finditer(file_content):
        column_name = match.group(1).lower()
        position = int(match.group(2))
        character = match.group(3)

        # Initialize dictionary for the column if it doesn't exist
        if column_name not in extracted_data:
            extracted_data[column_name] = {}

        # Store the character at its correct position
        extracted_data[column_name][position] = character

    results = {}
    for column_name, char_map in extracted_data.items():
        if char_map:
            # Sort the dictionary items by position (the key)
            sorted_chars = sorted(char_map.items())
            # Join the characters to form the final string
            reconstructed_string = "".join([char for pos, char in sorted_chars])
            results[column_name] = reconstructed_string

    return results

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_log_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()

    print("[*] Analyzing the log file to reconstruct the exfiltrated data...")

    results = extract_flag(content)
    print("\n" + "="*50)
    if not results:
        print("[-] No SQL injection data could be reconstructed from the file.")
    else:
        for column, data in results.items():
            print(f"[+] Reconstructed data for column '{column}':")
            print(f"    {data}\n")
    print("="*50)

if __name__ == "__main__":
    main()
```

If we run `python flag.py captured_packets.txt` we'll finally get our flag:
```bash
Desktop/WHY2025 CTF/Captcha-2.0 via 🐍 v3.13.3
❯ python flag.py captured_packets2.txt
[*] Analyzing the log file to reconstruct the exfiltrated data...

==================================================
[+] Reconstructed data for column 'sql':
    CREATE TABLE userTable (userName varchar(8),password varchar(40))

[+] Reconstructed data for column 'password':
    flag{caf496dfaa234481be31002ccf1dffb4}

==================================================
```

**flag{caf496dfaa234481be31002ccf1dffb4}**