from Crypto.Cipher import AES
import socket


empty_byte = 0b00000000
iv = bytes.fromhex('6571a3822f483bbf1d8ec87e1f4fed89')
K_prim = bytes.fromhex('8ac0f91054c003924d595a7996a99f5a')


def ECB_enc(text, key):
    enc_text = bytearray()
    text_bytes = bytearray(text, 'utf-8')
    cipher_enc = AES.new(key, AES.MODE_ECB)
    pad(text_bytes) # asigura ca ultimul bloc va avea lungimea 16 (bytes)

    for i in range(0, len(text_bytes), 16):
        block = bytes(text_bytes[i: i + 16])
        enc_block = cipher_enc.encrypt(block)
        enc_text += enc_block

    return enc_text


def CFB_enc(text, key):
    enc_text = bytearray()
    text_bytes = bytearray(text, 'utf-8')
    cipher = AES.new(key, AES.MODE_ECB)

    prev_block = cipher.encrypt(iv)  # blocul obtinut la pasul precedent
    for i in range(0, len(text_bytes), 16):
        block = bytes(text_bytes[i: i + 16])  # blocul curent

        enc_block = XOR(prev_block, block)
        enc_text += enc_block
        prev_block = enc_block

    return enc_text


def XOR(block1, block2):
    xor_block = bytearray()

    if len(block1) < len(block2):
        minblock, maxblock = block1, block2
        minlen, maxlen = len(block1), len(block2)

    else:
        minblock, maxblock = block2, block1
        minlen, maxlen = len(block2), len(block1)

    for i in range(minlen):
        byte = minblock[i] ^ maxblock[i]
        xor_block.append(byte)

    for i in range(minlen, maxlen):
        xor_block.append(maxblock[i])

    return bytes(xor_block)


def pad(text):
    # adauga 0-uri la capatul variabilei text,
    # pentru ca ultimul sau block sa fie de 16 bytes
    pad_length = 16 - (len(text) % 16)
    for i in range(pad_length):
        text.append(empty_byte)


def decrypt_key(enc_key):
    cipher = AES.new(K_prim, AES.MODE_ECB)
    dec_key = cipher.decrypt(enc_key)
    return dec_key


def get_key_from_km(mode):
    HOST = '127.0.0.1'
    PORT = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        s.sendall(bytes(mode, 'utf-8'))
        enc_key = s.recv(1024)
        print(f"\nReceived encrypted key from KM:", enc_key.hex())

        return enc_key


def connect_to_node_b(mode, enc_key):
    HOST = '127.0.0.1'
    PORT = 63021

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        s.sendall(bytes(mode, 'utf-8'))
        data = s.recv(1024)

        s.sendall(enc_key)
        print("Sent encrypted key to Node B")

        key = decrypt_key(enc_key)
        print("Decrypted key:", key.hex())

        response = s.recv(1024)
        print(f"Received response from Node B: \"{response.decode('utf-8')}\"")

        filename = input("\nEnter filename: ")

        f = open(filename, "r")
        text = f.read()

        if mode == "ECB":
            enc_text = ECB_enc(text, key)
        else:
            enc_text = CFB_enc(text, key)

        s.sendall(bytes(enc_text))
        print("\nSent encrypted file content to Node B.")


def main():
    valid_input = False

    while not valid_input:
        mode = input("\nMode(ECB/CFB): ").upper()
        if mode == "ECB" or mode == "CFB":
            valid_input = True

    enc_key = get_key_from_km(mode)
    connect_to_node_b(mode, enc_key)


if __name__ == '__main__':
    main()
