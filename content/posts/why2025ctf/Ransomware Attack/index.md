+++
draft = false
authors = ["Samuele Bella"]
title = "WHY2025 CTF - Ransomware Attack"
description = "WHY2025 CTF Ransomware Attack"
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

*Our company was attacked with ransomware. All of our files were encrypted. Luckily we could get most of those files back from backups, but an important file is still encrypted. We found some information in our network logs. Can you help to get this file back?*

This is the first and easiest Network challenge present in WHY2025 CTF.
We have a .pcap file which, on close inspection,  appears to be an FTP session.
{{< figure src="images/Ransomware_Attack.png" alt="Ransomware Attack" >}}

From this initial Wireshark view, we can start to isolate with the help of the **Info Column** the important packets such as:
- "Response: 331 Password required for administrator."
- "Response: 230 User administrator logged in."   
- "Request: SYST"  (According to [RFC 959](https://www.rfc-editor.org/rfc/rfc959), it's a request from the client to determine the server's operating system).
- "Response: 215 UNIX type: L8 (linux)"
- "Request: STOR encryptur.py" (This is an FTP command to store a file named "encryptur.py" on the server).
- *FTP-DATA:* The line with the "FTP-DATA" protocol shows the actual data transfer happening for the "encryptur.py" file.

If we take a look at the FTP-DATA packet, we can obtain the contents of the *encryptur.py* file:
```python
#!/usr/bin/env python3

# Ransomware encryptur
# The best encryptur on the planet, I wrote it myself

import sys

alphabet = 'abcdefghijklmnopqrstuvwxyz'

def shift_chars(text, pos):
	out = ""
	for letter in text:
		if letter in alphabet:
			letter_pos = (alphabet.find(letter) + pos) % 26
			new_letter = alphabet[letter_pos]
			out += new_letter
		else:
			out += letter
	return out
	
def encrypt_text(text):
	counter = 0
	encrypted_text = ""
	
	for i in range(0, len(text), 10):
		counter = (counter + 1) % 26
		encrypted_text += shift_chars(text[i:i+10], counter)
	return encrypted_text
	
if __name__ == '__main__':
	if len(sys.argv) < 2:
		print(f"Usage: {sys.argv[0]} <filename>")
		sys.exit(1)
	filename = sys.argv[1]
	with open(filename, "r") as f:
		data = f.read()
		encrypted_data = encrypt_text(data)
	with open(f"{filename}.encrypted", "w") as f:
		f.write(encrypted_data)
```
I would love to be as confident as the author of this code because, in fact, this code is not even remotely secure.
The core encryption logic is a form of a **Caesar cipher**, but with a twist.

- The `shift_chars` function performs a standard Caesar cipher shift on a given string, where each letter is shifted by a fixed position. The `(alphabet.find(letter) + pos) % 26` line is the standard modular arithmetic for this.
- The `encrypt_text` function iterates through the input text in chunks of 10 characters.
- For each 10-character chunk, it applies the `shift_chars` function with an increasing shift position (`counter`). The shift position starts at 1 and increments for each chunk, wrapping around from 25 back to 0. This makes it a **polyalphabetic substitution cipher**, which is slightly more complex than a simple Caesar cipher, but still relatively easy to break.

Now, going back to Wireshark, we can find the next FTP-DATA marked as (RETR important_file.txt.encrypted), this is our ransomware-encrypted file.

After exporting `important_file.txt.encrypted`, we can write a simple script which reverses the block-based Caesar cipher:
```python
#!/usr/bin/env python3

# Decryption script for the "best encryptur on the planet"
# Reverses the block-based Caesar cipher.

import sys

alphabet = 'abcdefghijklmnopqrstuvwxyz'

def decrypt_chars(text, pos):
    """
    Reverses the shift_chars function by subtracting the position.
    """
    out = ""
    for letter in text:
        if letter in alphabet:
            # Subtract the position to reverse the shift
            # The modulo operator (%) in Python handles negative results correctly
            letter_pos = (alphabet.find(letter) - pos) % 26
            original_letter = alphabet[letter_pos]
            out += original_letter
        else:
            # Non-alphabetic characters were not changed, so we leave them as is
            out += letter
    return out

def decrypt_text(encrypted_text):
    """
    Reverses the encrypt_text function.
    """
    counter = 0
    decrypted_text = ""
    
    # Process the text in the same 10-character chunks
    for i in range(0, len(encrypted_text), 10):
        # The key sequence is the same: 1, 2, 3, ...
        counter = (counter + 1) % 26
        
        # Get the current 10-character chunk
        chunk = encrypted_text[i:i+10]
        
        # Decrypt the chunk using the correct key and add it to our result
        decrypted_text += decrypt_chars(chunk, counter)
        
    return decrypted_text

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <encrypted_filename>")
        sys.exit(1)
    
    encrypted_filename = sys.argv[1]
    
    if encrypted_filename.endswith('.encrypted'):
        decrypted_filename = encrypted_filename[:-10] + ".decrypted"
    else:
        decrypted_filename = encrypted_filename + ".decrypted"

    print(f"[*] Reading encrypted file: {encrypted_filename}")
    try:
        with open(encrypted_filename, "r") as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        print(f"[!] Error: File not found at '{encrypted_filename}'")
        sys.exit(1)

    print("[*] Decrypting data...")
    decrypted_data = decrypt_text(encrypted_data)

    with open(decrypted_filename, "w") as f:
        f.write(decrypted_data)
        
    print(f"[+] Success! Decrypted file saved as: {decrypted_filename}")
```

After running `python decrypt.py important_file.txt.encrypted` we obtain the plaintext file which contains the flag:

```
Recipe Caesar Salad

Ingredients

For the Salad:

- 1 large head of Romaine lettuce, chopped
- 1 cup croutons (homemade or store-bought)
- 0,5 cup Parmesan cheese, shaved or grated

For the Dressing:

- 0,5 cup mayonnaise (or 0,5 cup mayo + 0,5 cup Greek yogurt for a lighter version)
- 2 tbsp lemon juice (freshly squeezed)
- 1 tsp Dijon mustard
- 1 tsp Worcestershire sauce
- 1 garlic clove, minced
- 2 anchovy fillets, finely chopped (or 0,5 tsp anchovy paste, optional)
- 0,25 cup olive oil
- Salt & black pepper, to taste
- a drizzle of flag{ad1c53bf1e00a9239d29edaadcda2964}

Instructions

Make the Dressing

- In a bowl, whisk together mayonnaise, lemon juice, Dijon mustard, Worcestershire sauce, minced garlic, and anchovies.
- Slowly drizzle in the olive oil while whisking to emulsify.
- Add salt and pepper to taste.

Prepare the Salad

- In a large salad bowl, toss chopped Romaine lettuce with croutons and Parmesan cheese.

Assemble

- Drizzle the dressing over the salad and gently toss to coat everything evenly.

Serve Immediately

- Garnish with extra Parmesan and croutons if desired.
- Enjoy with grilled chicken, shrimp, or salmon for a protein boost!
```

**flag{ad1c53bf1e00a9239d29edaadcda2964}**