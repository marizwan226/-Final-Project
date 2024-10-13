import struct
import hashlib

def leftrotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def sha256(message):
    # Initialize hash values
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # Initialize round constants
    k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
         0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5]

    # Preprocessing
    message = bytearray(message)
    ml = len(message) * 8
    message.append(0x80)
    while (len(message) * 8) % 512 != 448:
        message.append(0)
    message.extend(struct.pack('>q', ml))

    # Process the message in 16-word blocks
    for i in range(0, len(message), 64):
        w = [0] * 64
        for t in range(16):
            w[t] = struct.unpack('>I', message[i + t*4:i + t*4 + 4])[0]
        for t in range(16, 64):
            s0 = leftrotate(w[t-15], 7) ^ leftrotate(w[t-15], 18) ^ (w[t-15] >> 3)
            s1 = leftrotate(w[t-2], 17) ^ leftrotate(w[t-2], 19) ^ (w[t-2] >> 10)
            w[t] = (w[t-16] + s0 + w[t-7] + s1) & 0xffffffff

        # Initialize working variables
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Main loop
        for t in range(64):
            S1 = leftrotate(e, 6) ^ leftrotate(e, 11) ^ leftrotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + k[t%8] + w[t]) & 0xffffffff
            S0 = leftrotate(a, 2) ^ leftrotate(a, 13) ^ leftrotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        # Compute the new hash values
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        h5 = (h5 + f) & 0xffffffff
        h6 = (h6 + g) & 0xffffffff
        h7 = (h7 + h) & 0xffffffff

    # Convert the hash values to a hexadecimal string
    return '%08x%08x%08x%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4, h5, h6, h7)

# Download the Book of Mark text
import requests
response = requests.get('https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892')
message = response.text

# Compute the SHA-256 hash of the Book of Mark text
hash_value = sha256(message)

print('SHA-256 Hash:', hash_value)