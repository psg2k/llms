import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def pretty_print_hex(label, data, block_size=16):
    """Prints hex data in a formatted way."""
    hex_string = data.hex()
    print(f"{label:<8}: ", end="")
    # Group hex output into bytes for readability
    for i in range(0, len(hex_string), 2):
        if i > 0 and (i // 2) % block_size == 0:
            print("", end="\n          ") # Newline for new block
        print(hex_string[i:i+2], end=" ")
    print()

def demonstrate_pattern_preservation(mode, key, plaintext):
    """Encrypts data to see if patterns in plaintext are visible in ciphertext."""
    print(f"--- Testing Pattern Preservation (Mode: {mode}) ---")
    pretty_print_hex("input", plaintext)

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        padded_pt = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_pt)
    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC)
        padded_pt = pad(plaintext, AES.block_size)
        ciphertext = cipher.iv + cipher.encrypt(padded_pt)
    elif mode == "CFB":
        cipher = AES.new(key, AES.MODE_CFB)
        ciphertext = cipher.iv + cipher.encrypt(plaintext)
    
    pretty_print_hex("cipher", ciphertext)
    print("\nObservation: In ECB mode, identical plaintext blocks (e.g., '00 01 ... 0f') produce identical ciphertext blocks. This pattern is not preserved in CBC or CFB.\n")

def demonstrate_error_propagation(mode, key, plaintext):
    """Modifies a byte in the ciphertext to see how errors propagate during decryption."""
    print(f"--- Testing Error Propagation (Mode: {mode}) ---")
    pretty_print_hex("original", plaintext)

    # 1. Encrypt the original plaintext
    iv = get_random_bytes(AES.block_size)
    padded_pt = pad(plaintext, AES.block_size)
    
    if mode == "ECB":
        cipher_enc = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher_enc.encrypt(padded_pt)
    elif mode == "CBC":
        cipher_enc = AES.new(key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher_enc.encrypt(padded_pt)
    elif mode == "CFB":
        cipher_enc = AES.new(key, AES.MODE_CFB, iv=iv)
        ciphertext = cipher_enc.encrypt(plaintext)

    # 2. Corrupt one byte in the first block of the ciphertext
    # We choose byte 8 to modify
    error_position = 8
    corrupted_ciphertext = bytearray(ciphertext)
    original_byte = corrupted_ciphertext[error_position]
    corrupted_ciphertext[error_position] ^= 0xFF # Flip all bits of the byte
    
    print(f"-> Flipped byte at position {error_position} in the ciphertext (from {original_byte:02x} to {corrupted_ciphertext[error_position]:02x})")
    
    # 3. Decrypt the corrupted ciphertext
    decrypted_text = b""
    try:
        if mode == "ECB":
            cipher_dec = AES.new(key, AES.MODE_ECB)
            decrypted_padded = cipher_dec.decrypt(corrupted_ciphertext)
            decrypted_text = unpad(decrypted_padded, AES.block_size)
        elif mode == "CBC":
            # In CBC, the IV is prepended for transfer but not part of the ciphertext itself
            cipher_dec = AES.new(key, AES.MODE_CBC, iv=iv)
            decrypted_padded = cipher_dec.decrypt(corrupted_ciphertext)
            decrypted_text = unpad(decrypted_padded, AES.block_size)
        elif mode == "CFB":
            # In CFB, there is no padding to unpad
            cipher_dec = AES.new(key, AES.MODE_CFB, iv=iv)
            decrypted_text = cipher_dec.decrypt(corrupted_ciphertext)
    except (ValueError, KeyError) as e:
        decrypted_text = f"Decryption failed: {e}".encode()

    pretty_print_hex("decrypted", decrypted_text)
    
    if mode == "ECB":
        print("Observation: In ECB, the entire block containing the error is corrupted. Other blocks are unaffected.")
    elif mode == "CBC":
        print("Observation: In CBC, the entire block corresponding to the error is corrupted, AND the single corresponding bit in the *next* block is also flipped.")
    elif mode == "CFB":
        print("Observation: In CFB, only the single corresponding bit in the plaintext is flipped. The rest of the plaintext is unaffected.")
    print("-" * 60 + "\n")


if __name__ == "__main__":
    # Use a fixed key for reproducible results
    KEY = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

    # Plaintext with a repeating pattern (two identical blocks)
    PATTERNED_PLAINTEXT = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' * 2
    
    # A standard plaintext for error propagation test
    NORMAL_PLAINTEXT = b'This is a test message for our demo!!'

    # --- DEMONSTRATION ---
    
    # 1. Pattern Preservation Test
    demonstrate_pattern_preservation("ECB", KEY, PATTERNED_PLAINTEXT)
    demonstrate_pattern_preservation("CBC", KEY, PATTERNED_PLAINTEXT)
    demonstrate_pattern_preservation("CFB", KEY, PATTERNED_PLAINTEXT)

    # 2. Error Propagation Test
    demonstrate_error_propagation("ECB", KEY, NORMAL_PLAINTEXT)
    demonstrate_error_propagation("CBC", KEY, NORMAL_PLAINTEXT)
    demonstrate_error_propagation("CFB", KEY, NORMAL_PLAINTEXT)