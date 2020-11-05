from Crypto.Cipher import AES
import socket

HOST = '127.0.0.1'
PORT = 63021

empty_byte = 0b00000000
iv = bytes.fromhex('6571a3822f483bbf1d8ec87e1f4fed89')
K_prim = bytes.fromhex('8ac0f91054c003924d595a7996a99f5a')


def ECB_dec(enc_text, key):
    dec_text = bytearray()
    cipher_dec = AES.new(key, AES.MODE_ECB)

    for i in range(0, len(enc_text), 16):
        block = bytes(enc_text[i: i + 16])  # blocul curent care trebuie decriptat
        dec_block = cipher_dec.decrypt(block)
        dec_text += dec_block

    unpad(dec_text)
    return dec_text.decode('utf-8')


def CFB_dec(enc_text, key):
    dec_text = bytearray()
    cipher = AES.new(key, AES.MODE_ECB)

    prev_block = cipher.encrypt(iv)  # blocul obtinut la pasul precedent
    for i in range(0, len(enc_text), 16):
        block = bytes(enc_text[i: i + 16])  # blocul curent care trebuie decriptat

        dec_block = XOR(prev_block, block)
        dec_text += dec_block
        prev_block = block

    unpad(dec_text)
    return dec_text.decode('utf-8')


def unpad(text):
    for byte in reversed(text):
        if byte == empty_byte:
            text.remove(byte)
        else:
            return


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


def decrypt_key(enc_key):
    cipher = AES.new(K_prim, AES.MODE_ECB)
    dec_key = cipher.decrypt(enc_key)
    return dec_key


def main():
    print(f"\nAwaiting connection on port {PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:

            mode = conn.recv(1024)
            mode = mode.decode('utf-8')
            print("\nReceived mode from Node A:", mode)
            conn.sendall(b'ok')

            enc_key = conn.recv(1024)
            print(f"Received encrypted key from Node A:", enc_key.hex())

            key = decrypt_key(enc_key)
            print("Decrypted key:", key.hex())

            conn.sendall(b'Send file')
            print("Awaiting file from Node A...")

            enc_text = conn.recv(10240)
            print("\nReceived encrypted file from Node A:")
            print(enc_text.hex())

            if mode == "ECB":
                dec_text = ECB_dec(enc_text, key)
            else:
                dec_text = CFB_dec(enc_text, key)

            print(f"\nDecrypted file:")
            print(dec_text)


if __name__ == '__main__':
    main()
