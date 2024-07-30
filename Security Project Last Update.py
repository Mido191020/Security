from tkinter import *
from tkinter import ttk
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import base64
import math

root = Tk()

def cipher(mode):
    text = entry_text.get()
    method = select_algorithm.get()
    key = key_entry.get() if method in ["Monoalphabetic", "Playfair", "Polyalphabetic", "Vigenère", "Row Transposition", "Rail Fence", "DES", "AES"] else None

    def caesar(text, mode):
        shift = 3 if mode == "encrypt" else -3
        result = ""
        for char in text:
            if char.isupper():
                result += chr((ord(char) - 65 + shift) % 26 + 65)
            elif char.islower():
                result += chr((ord(char) - 97 + shift) % 26 + 97)
            else:
                result += char
        return result

    def monoalphabetic_cipher(text, key, mode="encrypt"):
        key = key.lower()
        alphabet = 'abcdefghijklmnopqrstuvwxyz'
        if mode == "decrypt":
            decryption_key = ''.join(sorted(alphabet, key=key.index))
            key = decryption_key
        result = ""
        for char in text:
            if char.isalpha():
                if char.islower():
                    result += key[ord(char) - ord('a')]
                elif char.isupper():
                    result += key[ord(char) - ord('A')].upper()
            else:
                result += char
        return result

    def playfair_cipher(text, key, mode="encrypt"):
        def generate_matrix(key):
            key = ''.join(sorted(set(key.upper()), key=key.upper().index))
            key = key.replace('J', '')
            remaining_chars = ''.join(sorted(set('ABCDEFGHIKLMNOPQRSTUVWXYZ') - set(key)))
            key += remaining_chars
            matrix = [key[i:i+5] for i in range(0, 25, 5)]
            return matrix

        def process_text(text, mode):
            text = text.upper().replace('J', 'I')
            if mode == "encrypt":
                processed_text = ""
                i = 0
                while i < len(text):
                    if i == len(text) - 1:
                        processed_text += text[i] + 'X'
                        i += 1
                    elif text[i] == text[i + 1]:
                        processed_text += text[i] + 'X'
                        i += 1
                    else:
                        processed_text += text[i] + text[i + 1]
                        i += 2
                text = processed_text
            return text

        def find_position(char, matrix):
            for row in range(5):
                for col in range(5):
                    if matrix[row][col] == char:
                        return row, col
            return None, None

        def encode_pair(pair, matrix, mode):
            row1, col1 = find_position(pair[0], matrix)
            row2, col2 = find_position(pair[1], matrix)
            if row1 == row2:
                col1 = (col1 + 1) % 5 if mode == "encrypt" else (col1 - 1) % 5
                col2 = (col2 + 1) % 5 if mode == "encrypt" else (col2 - 1) % 5
            elif col1 == col2:
                row1 = (row1 + 1) % 5 if mode == "encrypt" else (row1 - 1) % 5
                row2 = (row2 + 1) % 5 if mode == "encrypt" else (row2 - 1) % 5
            else:
                col1, col2 = col2, col1
            return matrix[row1][col1] + matrix[row2][col2]

        matrix = generate_matrix(key)
        text = process_text(text, mode)
        result = ''
        for i in range(0, len(text), 2):
            result += encode_pair(text[i:i+2], matrix, mode)
        return result
    
    def polyalphabetic_cipher(text, key, mode):
        result = ''
        key_index = 0
        key = [int(k) for k in key]  # Convert the key to a list of integers

        for char in text:
            if char.isalpha():
                shift = key[key_index]
                if mode == "encrypt":
                    if char.islower():
                        processed_char = chr((ord(char) - 97 + shift) % 26 + 97)
                    else:
                        processed_char = chr((ord(char) - 65 + shift) % 26 + 65)
                else:
                    if char.islower():
                        processed_char = chr((ord(char) - 97 - shift + 26) % 26 + 97)
                    else:
                        processed_char = chr((ord(char) - 65 - shift + 26) % 26 + 65)
                key_index = (key_index + 1) % len(key)
            else:
                processed_char = char  # Non-alphabetic characters are not processed
            result += processed_char

        return result

    def vigenere_cipher(text, key, mode="encrypt"):
        original_text = text
        text = text.replace(" ", "")
        key = key.upper()
        result = ""
        key_index = 0

        for i in range(len(text)):
            char = text[i]
            if char.isalpha():
                key_char = key[key_index % len(key)]
                key_index += 1
                shift = ord(key_char) - ord('A')
                if char.isupper():
                    char_code = ord(char) - ord('A')
                    if mode == "encrypt":
                        shifted_char_code = (char_code + shift) % 26
                    else:
                        shifted_char_code = (char_code - shift + 26) % 26
                    result += chr(shifted_char_code + ord('A'))
                else:
                    char_code = ord(char) - ord('a')
                    if mode == "encrypt":
                        shifted_char_code = (char_code + shift) % 26
                    else:
                        shifted_char_code = (char_code - shift + 26) % 26
                    result += chr(shifted_char_code + ord('a'))
            else:
                result += char

        # Adjusting the case of the output to match the input
        result_with_case = ''
        j = 0
        for i in range(len(original_text)):
            if original_text[i].isalpha():
                result_with_case += result[j]
                j += 1
            else:
                result_with_case += original_text[i]

        return result_with_case

    def row_transposition(text, key, mode="encrypt"):
        if mode == "encrypt":
            cipher = ""

            # track key indices
            k_indx = 0

            text_len = float(len(text))
            text_lst = list(text)
            key_lst = sorted(list(key))

            # calculate column of the matrix
            col = len(key)
            
            # calculate maximum row of the matrix
            row = int(math.ceil(text_len / col))

            # add the padding character '_' in empty
            # the empty cell of the matrix 
            fill_null = int((row * col) - text_len)
            text_lst.extend('_' * fill_null)

            # create Matrix and insert message and 
            # padding characters row-wise 
            matrix = [text_lst[i: i + col] for i in range(0, len(text_lst), col)]

            # read matrix column-wise using key
            for _ in range(col):
                curr_idx = key.index(key_lst[k_indx])
                cipher += ''.join([row[curr_idx] for row in matrix])
                k_indx += 1

            return cipher
        
        elif mode == "decrypt":
            msg = ""

            # track key indices
            k_indx = 0

            # track msg indices
            msg_indx = 0
            msg_len = float(len(text))
            msg_lst = list(text)

            # calculate column of the matrix
            col = len(key)
            
            # calculate maximum row of the matrix
            row = int(math.ceil(msg_len / col))

            # convert key into list and sort 
            # alphabetically so we can access 
            # each character by its alphabetical position.
            key_lst = sorted(list(key))

            # create an empty matrix to 
            # store deciphered message
            dec_cipher = []
            for _ in range(row):
                dec_cipher += [[None] * col]
                                                            
            # Arrange the matrix column wise according 
            # to permutation order by adding into new matrix
            for _ in range(col):
                curr_idx = key.index(key_lst[k_indx])

                for j in range(row):
                    dec_cipher[j][curr_idx] = msg_lst[msg_indx]
                    msg_indx += 1
                k_indx += 1

            # convert decrypted msg matrix into a string
            try:
                msg = ''.join(sum(dec_cipher, []))
            except TypeError:
                raise TypeError("This program cannot handle repeating words.")

            null_count = msg.count('_')

            if null_count > 0:
                return msg[: -null_count]

            return msg
        
    def rail_fence(text, key, mode="encrypt"):
        key = int(key)
        if mode == "encrypt":
            rail = [['\n' for i in range(len(text))]
                          for j in range(key)]
              
            dir_down = False
            row, col = 0, 0
              
            for i in range(len(text)):
                if (row == 0) or (row == key - 1):
                    dir_down = not dir_down
                  
                rail[row][col] = text[i]
                col += 1
                  
                if dir_down:
                    row += 1
                else:
                    row -= 1
            result = []
            for i in range(key):
                for j in range(len(text)):
                    if rail[i][j] != '\n':
                        result.append(rail[i][j])
            return("" . join(result))
        
        elif mode == "decrypt":
            rail = [['\n' for i in range(len(text))]
                          for j in range(key)]
              
            dir_down = None
            row, col = 0, 0
              
            for i in range(len(text)):
                if (row == 0) or (row == key - 1):
                    dir_down = not dir_down
                rail[row][col] = '*'
                col += 1
                  
                if dir_down:
                    row += 1
                else:
                    row -= 1
            index = 0
            for i in range(key):
                for j in range(len(text)):
                    if ((rail[i][j] == '*') and
                    (index < len(text))):
                        rail[i][j] = text[index]
                        index += 1
            result = []
            row, col = 0, 0
            for i in range(len(text)):
                if (row == 0) or (row == key - 1):
                    dir_down = not dir_down
                if (rail[row][col] != '*'):
                    result.append(rail[row][col])
                    col += 1
                if dir_down:
                    row += 1
                else:
                    row -= 1
            return("" . join(result))    

    def des_cipher(text, key, mode="encrypt"):
        key = key.ljust(8, ' ')[:8].encode('utf-8')
        cipher = DES.new(key, DES.MODE_ECB)
        if mode == "encrypt":
            padded_text = pad(text.encode('utf-8'), 8)
            encrypted_text = cipher.encrypt(padded_text)
            return base64.b64encode(encrypted_text).decode('utf-8')
        else:
            decoded_text = base64.b64decode(text)
            decrypted_text = unpad(cipher.decrypt(decoded_text), 8)
            return decrypted_text.decode('utf-8')
        
    def aes_cipher(text, key, mode="encrypt"):
        key = key.ljust(16, ' ')[:16].encode('utf-8')
        cipher = AES.new(key, AES.MODE_ECB)
        if mode == "encrypt":
            padded_text = pad(text.encode('utf-8'), 16)
            encrypted_text = cipher.encrypt(padded_text)
            return base64.b64encode(encrypted_text).decode('utf-8')
        else:
            decoded_text = base64.b64decode(text)
            decrypted_text = unpad(cipher.decrypt(decoded_text), 16)
            return decrypted_text.decode('utf-8')

    if method == "Caesar":
        processed_text = caesar(text, mode)
    elif method == "Monoalphabetic" and key:
        processed_text = monoalphabetic_cipher(text, key, mode)
    elif method == "Playfair" and key:
        processed_text = playfair_cipher(text, key, mode)
    elif method == "Polyalphabetic" and key:
        processed_text = polyalphabetic_cipher(text, key, mode)
    elif method == "Vigenère" and key:
        processed_text = vigenere_cipher(text, key, mode)
    elif method == "Row Transposition" and key:
        processed_text = row_transposition(text, key, mode)
    elif method == "Rail Fence" and key:
        processed_text = rail_fence(text, key, mode)
    elif method == "DES" and key:
        processed_text = des_cipher(text, key, mode)
    elif method == "AES" and key:
        processed_text = aes_cipher(text, key, mode)
    else:
        processed_text = "Algorithm not implemented yet or invalid key"

    output_textbox.delete('1.0', END)
    output_textbox.insert(END, processed_text)

def show_key_entry(event):
    method = select_algorithm.get()
    if method in ["Monoalphabetic", "Playfair", "Polyalphabetic", "Vigenère", "Row Transposition", "Rail Fence", "DES", "AES"]:
        key_label.grid(row=3, column=0, padx=10, pady=10)
        key_entry.grid(row=3, column=1, padx=10, pady=10, sticky="we")
    else:
        key_label.grid_remove()
        key_entry.grid_remove()

root.title("Security Project")
root.geometry("550x400")

name_app = Label(root, text="Cipher Application", font="bold 30", bg="red", fg="white")
name_app.grid(row=0, column=0, columnspan=2, sticky="we", pady=10)

label_select = Label(root, text="Select Algorithm", font="bold 15")
label_select.grid(row=1, column=0)

type_ciphers = [
    "Caesar",
    "Monoalphabetic",
    "Playfair",
    "Polyalphabetic",
    "Vigenère",
    "Rail Fence",
    "Row Transposition",
    "DES",
    "AES"
]

select_algorithm = ttk.Combobox(root, values=type_ciphers, width=30)
select_algorithm.grid(padx=10, pady=10, row=1, column=1)

entry_label = Label(root, text="Enter your text", font="bold 15")
entry_label.grid(row=2, column=0)

entry_text = ttk.Entry(root)
entry_text.grid(padx=10, pady=10, row=2, column=1, sticky="we")

key_label = Label(root, text="Enter key:", font="bold 15")
key_entry = ttk.Entry(root)

output_label = Label(root, text="Processed text is:", font="bold 15")
output_label.grid(row=4, column=0, padx=10 , pady = 10 , sticky = "nw")

output_textbox = Text(root, height=3, width=30 , font="Arial 15")
output_textbox.grid(row=4, column=1 , padx=10, pady=10)

select_algorithm.bind("<<ComboboxSelected>>", show_key_entry)
Button(root, text="Encrypt", bg="lightgray", font="Arial 12", command=lambda: cipher("encrypt")).grid(row=6, column=0, columnspan=2, pady=10, padx=150, ipadx=10, ipady=5, sticky="w")
Button(root, text="Decrypt", bg="lightgray", font="Arial 12", command=lambda: cipher("decrypt")).grid(row=6, column=1, columnspan=2, pady=10, padx=130, ipadx=10, ipady=5, sticky="e")

root.mainloop()
