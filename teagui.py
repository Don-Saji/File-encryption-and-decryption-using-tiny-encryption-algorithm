import os
import struct
import tkinter as tk
import secrets
from tkinter import filedialog, messagebox
from typing import Union

# TEA encryption constants
DELTA = 0x9E3779B9
NUM_ROUNDS = 32

# Helper functions for TEA encryption and decryption
def tea_encrypt(block, key):
    v0, v1 = struct.unpack('>2I', block)  # Unpack 8 bytes into two 32-bit integers
    k = struct.unpack('>4I', key)  # Unpack 16 bytes into four 32-bit integers
    sum = 0
    for _ in range(NUM_ROUNDS):
        sum = (sum + DELTA) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
    return struct.pack('>2I', v0, v1)

def tea_decrypt(block, key):
    v0, v1 = struct.unpack('>2I', block)
    k = struct.unpack('>4I', key)
    sum = (DELTA * NUM_ROUNDS) & 0xFFFFFFFF
    for _ in range(NUM_ROUNDS):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        sum = (sum - DELTA) & 0xFFFFFFFF
    return struct.pack('>2I', v0, v1)

# File encryption and decryption
def encrypt_file(input_path: str, output_path: str, key: bytes):
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes long.")

    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        data = infile.read()
        padding_length = (8 - len(data) % 8) % 8  # Calculate padding length
        data += b'\0' * padding_length  # Add padding

        # Encrypt in chunks
        for i in range(0, len(data), 8):
            chunk = data[i:i+8]
            encrypted_chunk = tea_encrypt(chunk, key)
            outfile.write(encrypted_chunk)

        # Append padding length as the last byte
        outfile.write(bytes([padding_length]))

def decrypt_file(input_path: str, output_path: str, key: bytes):
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes long.")

    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        # Read the entire file to determine padding
        data = infile.read()
        padding_length = data[-1]  # Last byte contains the padding length
        encrypted_data = data[:-1]  # Exclude the padding length byte

        # Decrypt in chunks
        for i in range(0, len(encrypted_data), 8):
            chunk = encrypted_data[i:i+8]
            decrypted_chunk = tea_decrypt(chunk, key)
            outfile.write(decrypted_chunk)

        # Remove padding
        if padding_length > 0:
            outfile.truncate(outfile.tell() - padding_length)

# GUI functions
def browse_file(entry):
    filename = filedialog.askopenfilename()
    if filename:
        entry.delete(0, tk.END)
        entry.insert(0, filename)

def browse_save(entry):
    filename = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("All Files", "*.*")])
    if filename:
        entry.delete(0, tk.END)
        entry.insert(0, filename)

def generate_key(key_entry):
    """Generate a random 16-byte key and insert it into the entry field."""
    key = secrets.token_bytes(16)  # Generate a 16-byte key
    key_hex = key.hex()  # Convert to hex
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key_hex)

def process_file(mode, input_path, output_path, key_hex):
    try:
        key = bytes.fromhex(key_hex)
        if len(key) != 16:
            raise ValueError("The key must be exactly 16 bytes.")

        if mode == "encrypt":
            encrypt_file(input_path, output_path, key)
            messagebox.showinfo("Success", f"File encrypted successfully and saved to {output_path}.")
        elif mode == "decrypt":
            decrypt_file(input_path, output_path, key)
            messagebox.showinfo("Success", f"File decrypted successfully and saved to {output_path}.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Setting up the GUI window
def create_gui():
    window = tk.Tk()
    window.title("File Encryption and Decryption")

    # Mode selection
    mode_label = tk.Label(window, text="Select mode:")
    mode_label.grid(row=0, column=0, padx=10, pady=10)

    mode_var = tk.StringVar()
    encrypt_radio = tk.Radiobutton(window, text="Encrypt", variable=mode_var, value="encrypt")
    decrypt_radio = tk.Radiobutton(window, text="Decrypt", variable=mode_var, value="decrypt")
    encrypt_radio.grid(row=1, column=0, padx=10, pady=10)
    decrypt_radio.grid(row=1, column=1, padx=10, pady=10)

    # Input file selection
    input_label = tk.Label(window, text="Input file:")
    input_label.grid(row=2, column=0, padx=10, pady=10)
    input_entry = tk.Entry(window, width=40)
    input_entry.grid(row=2, column=1, padx=10, pady=10)
    input_button = tk.Button(window, text="Browse", command=lambda: browse_file(input_entry))
    input_button.grid(row=2, column=2, padx=10, pady=10)

    # Output file selection
    output_label = tk.Label(window, text="Output file:")
    output_label.grid(row=3, column=0, padx=10, pady=10)
    output_entry = tk.Entry(window, width=40)
    output_entry.grid(row=3, column=1, padx=10, pady=10)
    output_button = tk.Button(window, text="Browse", command=lambda: browse_save(output_entry))
    output_button.grid(row=3, column=2, padx=10, pady=10)

    # Key input
    key_label = tk.Label(window, text="16-byte key (hex):")
    key_label.grid(row=4, column=0, padx=10, pady=10)
    key_entry = tk.Entry(window, width=40)
    key_entry.grid(row=4, column=1, padx=10, pady=10)

    # Generate Key Button
    generate_key_button = tk.Button(window, text="Generate Key", command=lambda: generate_key(key_entry))
    generate_key_button.grid(row=4, column=2, padx=10, pady=10)

    # Process button
    process_button = tk.Button(window, text="Process File", command=lambda: process_file(
        mode_var.get(), input_entry.get(), output_entry.get(), key_entry.get()
    ))
    process_button.grid(row=5, column=0, columnspan=3, padx=10, pady=20)

    window.mainloop()

# Run the GUI
if __name__ == "__main__":
    create_gui()
