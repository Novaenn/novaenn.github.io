+++
draft = false
authors = ["Samuele Bella"]
title = "WHY2025 CTF - Enlightenment"
description = "WHY2025 CTF Enlightenment"
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

*My lights have been acting weird lately. Can you shed some light on what's going on?  
ZigBee network key: d73581c3485ff294a9c70b840203fcc7*

Enlightenment is a medium difficulty challenge in the Network section of the WHY2025 CTF.

We are given a .pcap file which contains a network capture of a Zigbee communication.
{{< figure src="images/Capture.png" alt="Enlightenment Capture" >}}

Between all the noise, we can see that the **Zigbee Coordinator (ZC)** (The host with a short address of 0x0000) is sending several commands to host 0xb379 with the [Zigbee Cluster Library](https://docs.silabs.com/zigbee/8.2.1/zigbee-fundamentals/06-zigbee-cluster-library).
This repeating pattern might hide something valuable, like the flag for the challenge.

To show only the packets that have a Zigbee Cluster Library Frame inside, we can use the following display filter:
`zbee_zcl_general.onoff.cmd.srv_rx.id == 0x00 or zbee_zcl_general.onoff.cmd.srv_rx.id == 0x01`
This effectively shows us only the packets that have either a ZCL On command, or a ZCL Off command.

The problem now is extracting the command from these packets. During this CTF I found out that if you right-click a specific frame element, it's possible to apply it as a column on Wireshark!   
{{< figure src="images/Column.png" alt="Enlightenment Column" >}}

After doing so, I just exported the capture as a .csv file by going to File -> Export Packet Dissections -> As CSV.
The resulting CSV will have a column *Command* which we can leverage for later processing.
{{< figure src="images/CSV.png" alt="Enlightenment CSV" >}}

By writing a simple python script with the csv library, I was able to extract the command from every packet in order to create the final string.
The character for the packet x is 0 if the command is off, 1 otherwise.

After running the script, I noticed that the generated result was gibberish. Going back to the packet capture, I realized the sequence numbers of different packets were the same. This made it clear that to find the flag, it was necessary to ignore all duplicate packets and assemble the bit string using only the unique ones.

On Wireshark, I added the column regarding the Sequence Number and I exported the new .csv file.
{{< figure src="images/Capture 2.png" alt="Enlightenment Capture 2" >}}

Then, I simply added a check to skip duplicate sequence numbers: 
```python
import csv

input_file = 'Enlightenment.csv'

binary_sequence = ''
last_sequence_number = None

print("Processing Zigbee packet capture...")
print("-" * 30)

with open(input_file, newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    
    for row in reader:
        seq = row['Sequence Number'].strip()
        command = row['Command'].strip().lower()
        
        # Skip duplicate sequence numbers
        if seq == last_sequence_number:
            continue
        last_sequence_number = seq

        # Build binary
        if command == 'on':
            binary_sequence += '1'
        elif command == 'off':
            binary_sequence += '0'

# Convert binary to string (ASCII)
ascii_string = ''
for i in range(0, len(binary_sequence), 8):
    byte = binary_sequence[i:i+8]
    if len(byte) == 8:
        ascii_string += chr(int(byte, 2))

print("Binary sequence generated:")
print(binary_sequence)

print("\nDecoded string:")
print(ascii_string)

```

After running this script with `python solve.py` we get the flag:
```bash
Desktop/WHY2025 CTF/enlightenment via 🐍 v3.13.3
❯ python solve.py
Processing Zigbee packet capture...
------------------------------
Binary sequence generated:
0110011001101100011000010110011101111011001101000110001101100010001101010011010001100100001100110011100100110000001110010011000100110100001100010110011000110100011000100011010100110000011000100110010000111000001100000011001101100001001100100110011000110101011001010011100101100101001100100110010001111101

Decoded string:
flag{4cb54d3909141f4b50bd803a2f5e9e2d}
```

**flag{4cb54d3909141f4b50bd803a2f5e9e2d}**