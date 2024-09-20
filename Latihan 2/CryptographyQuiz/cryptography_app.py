import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox

# Vigenere Cipher Implementation
class VigenereCipher:
    def validate_key(self, key):
        if len(key) < 12:
            raise ValueError("Key must be at least 12 characters long.")
    
    def encrypt(self, plaintext, key):
        self.validate_key(key)
        key = key.upper()
        encrypted_text = ''
        key_repeated = (key * (len(plaintext) // len(key)) + key[:len(plaintext) % len(key)])

        for i in range(len(plaintext)):
            if plaintext[i].isalpha():
                shift = ord(key_repeated[i]) - ord('A')
                if plaintext[i].isupper():
                    encrypted_text += chr((ord(plaintext[i]) + shift - ord('A')) % 26 + ord('A'))
                else:
                    encrypted_text += chr((ord(plaintext[i]) + shift - ord('a')) % 26 + ord('a'))
            else:
                encrypted_text += plaintext[i]
        return encrypted_text

    def decrypt(self, ciphertext, key):
        self.validate_key(key)
        key = key.upper()
        decrypted_text = ''
        key_repeated = (key * (len(ciphertext) // len(key)) + key[:len(ciphertext) % len(key)])

        for i in range(len(ciphertext)):
            if ciphertext[i].isalpha():
                shift = ord(key_repeated[i]) - ord('A')
                if ciphertext[i].isupper():
                    decrypted_text += chr((ord(ciphertext[i]) - shift - ord('A')) % 26 + ord('A'))
                else:
                    decrypted_text += chr((ord(ciphertext[i]) - shift - ord('a')) % 26 + ord('a'))
            else:
                decrypted_text += ciphertext[i]
        return decrypted_text

# Playfair Cipher Implementation
class PlayfairCipher:
    def __init__(self, key):
        self.key = key.upper().replace('J', 'I')
        self.matrix = self.create_matrix()

    def create_matrix(self):
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        key_unique = ''.join(sorted(set(self.key), key=self.key.index))
        key_string = key_unique + ''.join([c for c in alphabet if c not in key_unique])
        return [list(key_string[i:i + 5]) for i in range(0, 25, 5)]

    def encrypt(self, plaintext):
        plaintext = plaintext.upper().replace('J', 'I').replace(' ', '')
        formatted_plaintext = []
        i = 0

        while i < len(plaintext):
            a = plaintext[i]
            b = plaintext[i + 1] if i + 1 < len(plaintext) and plaintext[i] != plaintext[i + 1] else 'X'
            formatted_plaintext.append(a + b)
            i += 2 if a != b else 1
        
        ciphertext = ''
        for digraph in formatted_plaintext:
            row1, col1 = divmod(self.find_position(digraph[0]), 5)
            row2, col2 = divmod(self.find_position(digraph[1]), 5)

            if row1 == row2:
                ciphertext += self.matrix[row1][(col1 + 1) % 5]
                ciphertext += self.matrix[row2][(col2 + 1) % 5]
            elif col1 == col2:
                ciphertext += self.matrix[(row1 + 1) % 5][col1]
                ciphertext += self.matrix[(row2 + 1) % 5][col2]
            else:
                ciphertext += self.matrix[row1][col2]
                ciphertext += self.matrix[row2][col1]

        return ciphertext

    def find_position(self, char):
        for i, row in enumerate(self.matrix):
            if char in row:
                return i * 5 + row.index(char)

# Hill Cipher Implementation
class HillCipher:
    def __init__(self, key_matrix):
        self.key_matrix = np.array(key_matrix)
        self.inverse_key_matrix = self.modular_inverse_matrix(self.key_matrix)

    def modular_inverse_matrix(self, matrix):
        det = int(np.round(np.linalg.det(matrix)))
        det_inv = pow(det, -1, 26)
        adjugate_matrix = np.round(np.linalg.inv(matrix) * det).astype(int)
        return (det_inv * adjugate_matrix) % 26

    def encrypt(self, plaintext):
        plaintext_numbers = [ord(char) - ord('A') for char in plaintext.upper() if char.isalpha()]
        ciphertext_numbers = []

        for i in range(0, len(plaintext_numbers), 2):
            block = plaintext_numbers[i:i+2]
            if len(block) < 2:
                block.append(0)
            encrypted_block = np.dot(self.key_matrix, block) % 26
            ciphertext_numbers.extend(encrypted_block)

        return ''.join(chr(num + ord('A')) for num in ciphertext_numbers)

    def decrypt(self, ciphertext):
        ciphertext_numbers = [ord(char) - ord('A') for char in ciphertext.upper() if char.isalpha()]
        decrypted_numbers = []

        for i in range(0, len(ciphertext_numbers), 2):
            block = ciphertext_numbers[i:i+2]
            decrypted_block = np.dot(self.inverse_key_matrix, block) % 26
            decrypted_numbers.extend(decrypted_block)

        return ''.join(chr(int(num) + ord('A')) for num in decrypted_numbers)

# GUI Application Using Tkinter
class CryptographyApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Cryptography Program")
        self.create_widgets()

    def create_widgets(self):
        self.label_key = tk.Label(self.master, text="Enter Key:")
        self.label_key.pack()

        self.entry_key = tk.Entry(self.master)
        self.entry_key.pack()

        self.label_plaintext = tk.Label(self.master, text="Enter Plaintext:")
        self.label_plaintext.pack()

        self.entry_plaintext = tk.Text(self.master, height=5)
        self.entry_plaintext.pack()

        self.encrypt_button = tk.Button(self.master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(self.master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack()

        self.result_label = tk.Label(self.master, text="Result:")
        self.result_label.pack()

        self.result_text = tk.Text(self.master, height=5)
        self.result_text.pack()

    def encrypt(self):
        key = self.entry_key.get()
        plaintext = self.entry_plaintext.get("1.0", tk.END).strip()

        # Choose Vigenere Cipher for demonstration. You can swap with Playfair or Hill.
        cipher = VigenereCipher()
        encrypted_text = cipher.encrypt(plaintext, key)
        
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, encrypted_text)

    def decrypt(self):
        key = self.entry_key.get()
        ciphertext = self.entry_plaintext.get("1.0", tk.END).strip()

        # Choose Vigenere Cipher for demonstration. You can swap with Playfair or Hill.
        cipher = VigenereCipher()
        decrypted_text = cipher.decrypt(ciphertext, key)

        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, decrypted_text)

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptographyApp(root)
    root.mainloop()
