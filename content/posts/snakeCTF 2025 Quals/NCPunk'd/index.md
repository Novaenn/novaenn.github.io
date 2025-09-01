+++
draft = false
authors = ["Samuele Bella"]
title = "SnakeCTF 2025 Quals - NCPunk'd"
description = "SnakeCTF 2025 Quals NCPunk'd"
date = "2025-09-01"
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
series = ["SnakeCTF 2025 Quals"]
+++

*Who the hell uses IPX and NCP in 2025? This guy. Can you help me find the flag?*
NCPunk'd is a Network challenge from the SnakeCTF Quals.

The .pcap file we are given seems to be a capture of a legacy Novell NetWare network. The packets show a client performing DNS queries, communicating with a router via RIP, and then establishing a connection and interacting with a NetWare server using the IPX, SAP, and NCP protocols.
{{< figure src="images/NCPunkd_Capture.png" alt="NCPunk'd Capture" >}}

The **Internetwork Packet Exchange** (IPX) is a network-layer protocol used during the 1980s while the **Network Control Protocol** (NCP) is a communication protocol which provided the transport layer of the protocol stack running on host computers of the ARPANET.

From frame 180 onwards, we have a huge number of client requests "C Get Volume and Purge Information for Volume" which means that the client is making a request to the server to get information about a specific volume.

Frame 6235 is the next interesting packet. Here, the client is performing a "*C Obtain Info for: admin.logs*" command, which asks the server for various information regarding the file admin.logs. A couple of packets later we see the command "*C Open/Create File or Subdirectory*" on the admin.logs file. This means that the client has the intention of reading the file and has opened a file handle for it.
This handle is used in "*C Read From File*" and "*C Close File*. 

This log file in particular does not contain anything exciting, but if we apply the display filter `_ws.col.info contains "C Read From File"` we can see every Read From File command that the client sent to the server.

Between them, Frame 6731 "*C Read From File - 0xea01e9010000*"  is the client request for reading the file called *flag.enc*, which is obviously very interesting. Unfortunately, the file contained the following:
>s9h4Vitm2h6J7cLrYc0w9zfRsBmAzLw/kNe0dlZbRguuDP9S1e4ofDxZWf6RXXXTCF6eRSkQeTWoUuSxKx0i8A==

which seems a simple Base64 Encoding but it is not. :(

Thankfully, just below we see a "*C Obtain Info for: admin_diary.txt*" which is an unusual filename.
The file contained the following message:
```
So you got your hands on the flag file already? Impressive.
But lets be clear: the real challenge isnt **finding** the flag  its **earning** it.
Sure, the encryption tool is in there somewhere...  
But good luck reversing **that**.
~~ ,_sys_admin_, ~~
```
Thank god Mr. sys_admin told us that the encryption tool is inside this packet capture otherwise I would have probably bashed my head figuring out how to decrypt that string.

On Wireshark, we can CTRL-F and search for all occurences of the string "Encrypt" in the packets and guess what? We find an *encrypt.pyc* file which is read, great!
The content read is not humanly-readable since a .pyc file is a Python compiled file that contains bytecode. 

Luckily for us, python decompilers such as [Uncompyle6](https://github.com/rocky/python-uncompyle6) exist. They essentially translate Python bytecode back into equivalent Python source code.

First of all, however, we need to extract these files from the packet capture. 
To do this, we can write a magic python file which, with the help of scapy, extracts the files for us, even if they are fragmented into multiple packets such as the *encrypt.pyc* file:
{{< figure src="images/encrypt.pyc.png" alt="encrypt.pyc packet communication" >}}

```python
import sys
from scapy.all import rdpcap, Raw

# The size of the combined IPX and NCP headers to strip from each packet payload.
# (30-byte IPX header + 10-byte NCP Reply header)
HEADER_SIZE_TO_STRIP = 40

def extract_and_clean_frames(pcap_file, output_file, frame_numbers):
    print(f"[*] Reading packets from '{pcap_file}'...")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Error reading pcap file: {e}")
        return

    data_chunks = []
    
    print(f"[*] Targeting frames: {frame_numbers}")
    print(f"[*] Will strip {HEADER_SIZE_TO_STRIP} header bytes from each frame's payload.")
    
    for frame_num in frame_numbers:
        index = frame_num - 1
        
        if index < 0 or index >= len(packets):
            print(f"[!] Warning: Frame {frame_num} is out of bounds. Skipping.")
            continue
            
        packet = packets[index]
        
        if packet.haslayer(Raw):
            full_payload = packet[Raw].load
            
            # Check if the payload is large enough to strip the header
            if len(full_payload) > HEADER_SIZE_TO_STRIP:
                actual_data = full_payload[HEADER_SIZE_TO_STRIP:]
                data_chunks.append(actual_data)
                print(f"    [+] Frame {frame_num}: Extracted {len(actual_data)} bytes of data after stripping header.")
            else:
                print(f"    [!] Warning: Frame {frame_num} payload is too small ({len(full_payload)} bytes) to strip header. Skipping.")
        else:
            print(f"    [!] Warning: Frame {frame_num} has no raw data payload. Skipping.")

    if not data_chunks:
        print("\n[-] No data was extracted. Operation failed.")
        return

    print("\n[*] Combining cleaned data chunks...")
    full_data = b''.join(data_chunks)
    
    print(f"[*] Writing {len(full_data)} bytes to '{output_file}'...")
    with open(output_file, 'wb') as f:
        f.write(full_data)
        
    print(f"[+] Success! Clean file saved as '{output_file}'.")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python extract_frames_clean.py <input.pcap> <output_file> <frame_num1> <frame_num2> ...")
        sys.exit(1)
        
    pcap_path = sys.argv[1]
    output_path = sys.argv[2]
    
	frame_nums_to_extract = [int(n) for n in sys.argv[3:]]
    extract_and_clean_frames(pcap_path, output_path, frame_nums_to_extract)
``` 
Scapy probably has a better way to extract files, but this script essentially takes as input the frame numbers of the server's *R OK* responses, extracts the entire frame, and removes the IPX and NCP headers before saving the file.
With this, we can easily extract our *flag.enc* and *encrypt.pyc* files!

After the extraction, we use uncompyle on the .pyc file by running `uncompyle6 encrypt.pyc > encrypt.py`.
We finally get our encrypt.py: SIKE!
```bash
~
❯ uncompyle6 Desktop/SnakeCTF2025/NCPunkd/encrypt.pyc
# uncompyle6 version 3.9.2
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.13.3 (main, Aug 14 2025, 11:53:40) [GCC 14.2.0]
# Embedded file name: encrypt.py
# Compiled at: 2025-07-10 18:03:40
# Size of source mod 2**32: 2310 bytes
Traceback (most recent call last):
  File "/home/novaen/.local/bin/uncompyle6", line 8, in <module>
    sys.exit(main_bin())
             ~~~~~~~~^^
  ...
  ...
  ...
  ...
  File "/home/novaen/.local/lib/python3.13/site-packages/uncompyle6/scanner.py", line 126, in __init__
    exec("self.opc = %s" % v_str)
    ~~~~^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<string>", line 1, in <module>
NameError: name 'opcode_38' is not defined
```
We get a `name 'opcode_38'is not defined`, this is because wwe have a version mismatch. The uncompyle6 binary decompiles from the system's python version (3.13.3 in this case) and if the bytecode is from an older version (3.8.0) we risk having deprecated opcodes that are not recognized by modern versions.

To fix this, I used [uv](https://docs.astral.sh/uv/), "An extremely fast Python package and project manager, written in Rust." which helped me create a quick virtual environment with python 3.8.0:
```bash
uv init
uv venv --python=3.8
uv add uncompyle6
uv run uncompyle6 encrypt.pyc > encrypt.py
```

This creates the following encrypt.py file:
```python
# uncompyle6 version 3.9.2
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.12.10 (main, Apr  9 2025, 04:03:51) [Clang 20.1.0 ]
# Embedded file name: encrypt.py
# Compiled at: 2025-07-10 18:03:40
# Size of source mod 2**32: 2310 bytes
import sys, base64

def _0x4a2b1f(s):
    r = []
    for c in s:
        r.append(chr(ord(c) + 1))
    else:
        return "".join(r)


def _0x7c8d3e(data):
    k = [
     66, 26, 127, 51, 142, 33, 148, 87]
    a = []
    for i, b in enumerate(data):
        a.append(b ^ k[i % len(k)])
    else:
        return bytes(a)


def _0x9f1e2d(text):
    m = []
    for _ in range(4):
        row = []
        for _ in range(4):
            row.append(0)
        else:
            m.append(row)

    else:
        p = text + "\x00" * (16 - len(text) % 16)
        bs = []
        for i in range(0, len(p), 16):
            block = p[i[:i + 16]]
            for _0x8a1ed4 in range(4):
                for _0x2b5fd4 in range(4):
                    m[_0x8a1ed4][_0x2b5fd4] = ord(block[_0x8a1ed4 * 4 + _0x2b5fd4])
                else:
                    for _ in range(3):
                        temp = m[0][0]
                        m[0][0] = m[1][1]
                        m[1][1] = m[2][2]
                        m[2][2] = m[3][3]
                        m[3][3] = temp
                        for _0x8a1ed4 in range(4):
                            m[_0x8a1ed4] = m[_0x8a1ed4][1[:None]] + [m[_0x8a1ed4][0]]
                        else:
                            br = []
                            for _0x8a1ed4 in range(4):
                                for _0x2b5fd4 in range(4):
                                    br.append(m[_0x8a1ed4][_0x2b5fd4])
                                else:
                                    bs.append(bytes(br))

                            else:
                                return (b'').join(bs)


class _0x5e3a7c:

    def __init__(self):
        self.x = 25214903917L
        self.y = 11
        self.z = 281474976710656L

    def _0x2f4e1b(self, s):
        self.x = s

    def _0x6d8c9a(self):
        self.x = self.x * 25214903917L + 11 & 281474976710655L
        return self.x >> 16


def _0x3b9f2e(data, s):
    _0x2fde4c = _0x5e3a7c()
    _0x2fde4c._0x2f4e1b(s)
    r = []
    for b in data:
        rand_val = _0x2fde4c._0x6d8c9a() & 255
        r.append(b ^ rand_val)
    else:
        return bytes(r)


def _0x3efde3(_0x5b9c2f):
    _0xfe093c = _0x4a2b1f(_0x5b9c2f)
    _0x4d22aa = _0xfe093c[None[None:-1]]
    _0xc8b3f1 = _0x9f1e2d(_0x4d22aa)
    _0x7e5a10 = _0x7c8d3e(_0xc8b3f1)
    s = len(_0x5b9c2f) * 1337 + ord(_0x5b9c2f[0]) * 42
    _0x1d9b4e = _0x3b9f2e(_0x7e5a10, s)
    final = base64.b64encode(_0x1d9b4e).decode()
    print(f"Encrypted: {final}")
    return final


def main():
    if len(sys.argv) != 2:
        sys.exit(1)
    _0x3efde3(sys.argv[1])


if __name__ == "__main__":
    main()
```
Not really readable huh?

Renaming some functions and looking at the main operations we can see that this encryption function does basically the following things: 

1. `_0x4a2b1f`: This function is a custom Caesar Cipher implementation, it iterates through the input string and increments the ASCII value of each character by 1.
    - To reverse this we need to simply decrement the ASCII value of each character by 1.
2. Inside `_0x3efde3` the line *_0x4d22aa = _0xfe093c[None[None:-1]]* is a decompilation artifact. A very common operation that looks like this is a string reversal: *_0xfe093c[::-1]* so we'll assume that this is the intended operation.
    - To reverse this we simply reverse the string again.
3. `_0x9f1e2d`: This is the most complex function. It pads the input to a multiple of 16 bytes, processes it in 16-byte blocks, and scrambles each block using a 4x4 matrix. The scrambling consists of two operations repeated 3 times:
    1.  Diagonal Rotation: The elements on the main diagonal are rotated: (d0, d1, d2, d3) -> (d3, d0, d1, d2).
    2. Row Shift Left: Each row is shifted to the left by one position.
    - To reverse these operations we must perform the inverse operations in the reverse order, also 3 times:
        1. Row Shift Right: Shift each row to the right by one position.
        2.  Diagonal Rotation Backwards: Rotate the diagonal elements backwards: (d0, d1, d2, d3) -> (d1, d2, d3, d0).
        - Finally, we'll need to remove the null-byte padding (\x00) that was added. (Guess who forgot about it and spent 20 minutes wondering why the decrypted string was gibberish?)
4. `_0x7c8d3e`: This function XORs the data with a fixed 8-byte key [66, 26, 127, 51, 142, 33, 148, 87], nothing special.
    - To reverse this we know that the XOR is its own inverse, so we just need to apply the same function again.
5. `_0x3b9f2e`: This function uses a custom [Linear Congruential Generator ](https://en.wikipedia.org/wiki/Linear_congruential_generator)(LCG) to create a pseudo-random stream of bytes, which is then XORed with the data. The LCG is seeded by the value s. This seed is calculated as: `len(plaintext) * 1337 + ord(plaintext[0]) * 42`. This is a problem, as we don't know the original plaintext's length (We do know the first character since every flag in the CTF starts with the prefix **snakeCTF{** so `plaintext[0] = "s"` and `ord(plaintext[0]) = 115`.
    - To reverse this is we need to apply the same function with the correct seed s.
6. In `_0x3efde3` we see a *base64.b64encode* which tells us that the final result is Base64 encoded (and that's why the format was familiar lol).
    - To reverse this we just *base64.b64decode* the data from flag.enc.

Most of these steps are easy to reverse so our *decrypt.py* file should be easy to write. However, we need to bruteforce `len(plaintext)` in order to find the seed s needed in `_0x3b9f2e`.

The complete decrypt.py file is the following:
```python
import sys
import base64
import string

class LCG:
    def __init__(self):
        self.state = 25214903917
        self.multiplier = 25214903917
        self.addend = 11
        self.mask = (1 << 48) - 1

    def seed(self, s):
        self.state = s

    def next_rand(self):
        self.state = (self.state * self.multiplier + self.addend) & self.mask
        return self.state >> 16

def lcg_stream_xor(data, s):
    lcg = LCG()
    lcg.seed(s)
    result = []
    for byte in data:
        rand_val = lcg.next_rand() & 255
        result.append(byte ^ rand_val)
    return bytes(result)

def repeating_key_xor(data):
    key = [66, 26, 127, 51, 142, 33, 148, 87]
    result = []
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % len(key)])
    return bytes(result)

def reverse_matrix_scramble(data: bytes) -> bytes:
    decrypted_blocks = []
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        if len(block) < 16:
            decrypted_blocks.append(block)
            continue

        matrix = [[0] * 4 for _ in range(4)]
        for r in range(4):
            for c in range(4):
                matrix[r][c] = block[r * 4 + c]

        for _ in range(3):
            # 1. Inverse of Row Shift Left -> Row Shift Right
            for r in range(4):
                matrix[r] = [matrix[r][-1]] + matrix[r][:-1]

            # 2. Inverse of Diagonal Rotate Left -> Diagonal Rotate Right
            temp = matrix[0][0]
            matrix[0][0] = matrix[3][3]
            matrix[3][3] = matrix[2][2]
            matrix[2][2] = matrix[1][1]
            matrix[1][1] = temp

        block_result = bytearray()
        for r in range(4):
            for c in range(4):
                block_result.append(matrix[r][c])
        decrypted_blocks.append(block_result)

    result = b''.join(decrypted_blocks)
    return result.rstrip(b'\x00')

def reverse_caesar_cipher(s: str) -> str:
    result = []
    for char in s:
        result.append(chr(ord(char) - 1))
    return "".join(result)

def is_plausible_plaintext(text: str) -> bool:
    # At least 80% of characters should be printable (excluding tabs, newlines)
    printable_chars = set(string.printable) - set('\t\n\r\x0b\x0c')
    printable_count = sum(1 for char in text if char in printable_chars)
    if len(text) == 0:
        return False
    return (printable_count / len(text)) > 0.8 and ("{" in text or "}" in text)

def decrypt(encrypted_data: bytes, first_char: str):
    print(f"Starting decryption process...")
    
    # Brute-force the first character of the original plaintext
    first_char_ord = ord(first_char)
    print(f"[*] Testing assumption: flag starts with '{first_char}'")
	
    # Brute-force the length of the original plaintext (expanded range)
    for length in range(10, 80):
        # 1. Calculate the LCG seed 's'
        s = length * 1337 + first_char_ord * 42

        # 2. Reverse LCG Stream Cipher
        data_after_lcg = lcg_stream_xor(encrypted_data, s)
        
        # 3. Reverse Repeating-Key XOR
        data_after_repeating_key = repeating_key_xor(data_after_lcg)
        
        # 4. Reverse Matrix Scrambling
        unmangled_bytes = reverse_matrix_scramble(data_after_repeating_key)

        # 5. Reverse the string reversal (and decode)
        try:
            unmangled_str = unmangled_bytes.decode('utf-8')
            unreversed_str = unmangled_str[::-1]
        except UnicodeDecodeError:
            continue
            
        # 6. Reverse the Caesar Cipher
        plaintext = reverse_caesar_cipher(unreversed_str)

        # 7. Check if the result is plausible plaintext
        if is_plausible_plaintext(plaintext):
            print(f"  [+] Possible match found (length={length}, first_char='{first_char}'): {plaintext}")
        return None

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <encrypted_file> first_char")
        sys.exit(1)
        
    encrypted_file = sys.argv[1]
    first_chars_to_try = sys.argv[2]
    
    try:
        with open(encrypted_file, 'r') as f:
            b64_encoded_data = f.read().strip()
    except FileNotFoundError:
        print(f"Error: File not found at '{encrypted_file}'")
        sys.exit(1)
        
    try:
        encrypted_data = base64.b64decode(b64_encoded_data)
    except base64.binascii.Error:
        print("Error: The input file does not contain valid Base64 data.")
        sys.exit(1)

    decrypt(encrypted_data, first_chars_to_try)

if __name__ == "__main__":
    main()
```

At last, by running `python decrypt.py flag.enc s"` we get:
```bash
NCPunkd via 🐍 v3.13.3
❯ python decrypt.py flag.enc s
Starting decryption process...
[*] Testing assumption: flag starts with 's'
  [+] Possible match found (length=49, first_char='s'): snakeCTF{NCP_5lurp1ng_w1th_b3p1_d87afbfe6f07457b}
```

**snakeCTF{NCP_5lurp1ng_w1th_b3p1_d87afbfe6f07457b}**