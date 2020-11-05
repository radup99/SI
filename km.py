from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket

K = get_random_bytes(16)
K_prim = bytes.fromhex('8ac0f91054c003924d595a7996a99f5a')

HOST = '127.0.0.1'
PORT = 65432


def encrypt_key(K):
    cipher = AES.new(K_prim, AES.MODE_ECB)
    K_enc = cipher.encrypt(K)
    return K_enc


def print_keys():
    print("\nKeys: ")
    print("K: ", K.hex())
    print("K\':", K_prim.hex())


def main():
    print_keys()
    print(f"\nAwaiting connection on port {PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            key_enc = encrypt_key(K)
            print(f"\nEncrypted K:", key_enc.hex())
            conn.sendall(key_enc)
            print("Sent encrypted key to Node A")


if __name__ == '__main__':
    main()
