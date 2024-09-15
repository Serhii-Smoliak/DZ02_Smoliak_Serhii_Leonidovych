import math
import os


# Helper functions for table cipher
def create_matrix(text, key):
	matrix = []
	key_length = len(key)
	num_rows = math.ceil(len(text) / key_length)

	index = 0
	for i in range(num_rows):
		row = []
		for j in range(key_length):
			if index < len(text):
				row.append(text[index])
			else:
				row.append(' ')
			index += 1
		matrix.append(row)
	return matrix


def table_encrypt(text, key):
	matrix = create_matrix(text, key)
	key_order = sorted(range(len(key)), key=lambda k: key[k])  # Get column order based on the key
	encrypted_text = ""

	for col_index in key_order:
		for row in matrix:
			encrypted_text += row[col_index]

	return encrypted_text


def table_decrypt(cipher_text, key):
	key_length = len(key)
	num_rows = math.ceil(len(cipher_text) / key_length)
	key_order = sorted(range(len(key)), key=lambda k: key[k])  # Get column order based on the key

	columns = ['' for _ in range(key_length)]
	index = 0
	for col_index in key_order:
		for _ in range(num_rows):
			if index < len(cipher_text):
				columns[col_index] += cipher_text[index]
			index += 1

	decrypted_text = ''
	for i in range(num_rows):
		for col_index in range(key_length):
			if i < len(columns[col_index]):
				decrypted_text += columns[col_index][i]

	return decrypted_text.strip()


# Helper functions for Vigenère cipher
def vigenere_encrypt(text, key):
	key_length = len(key)
	encrypted_text = ""

	for i, char in enumerate(text):
		if char.isalpha():
			shift = ord(key[i % key_length].upper()) - ord('A')
			base = ord('A') if char.isupper() else ord('a')
			encrypted_text += chr((ord(char) - base + shift) % 26 + base)
		else:
			encrypted_text += char

	return encrypted_text


def vigenere_decrypt(cipher_text, key):
	key_length = len(key)
	decrypted_text = ""

	for i, char in enumerate(cipher_text):
		if char.isalpha():
			shift = ord(key[i % key_length].upper()) - ord('A')
			base = ord('A') if char.isupper() else ord('a')
			decrypted_text += chr((ord(char) - base - shift) % 26 + base)
		else:
			decrypted_text += char

	return decrypted_text


def main():
	base_dir = "../src/files"
	input_filename = os.path.join(base_dir, 'input_text.txt')

	# Read text from file
	with open(input_filename, 'r', encoding='utf-8') as file:
		text = file.read()

	# Level 1: Table cipher with key "MATRIX"
	key1 = "MATRIX"
	encrypted_text_matrix = table_encrypt(text, key1)
	print(f"Encrypted text with key '{key1}': {encrypted_text_matrix}")

	decrypted_text_matrix = table_decrypt(encrypted_text_matrix, key1)
	print(f"Decrypted text with key '{key1}': {decrypted_text_matrix}")

	# Level 2: Vigenère cipher followed by table cipher with keys "SECRET" and "CRYPTO"
	key2 = "SECRET"
	key3 = "CRYPTO"

	# First stage: Vigenère cipher
	vigenere_encrypted_text = vigenere_encrypt(text, key2)
	print(f"Vigenère encrypted text with key '{key2}': {vigenere_encrypted_text}")

	# Second stage: Table cipher with the result
	double_encrypted_text = table_encrypt(vigenere_encrypted_text, key3)
	print(f"Double encrypted text with keys '{key2}' and '{key3}': {double_encrypted_text}")

	# Decrypt the double encrypted text
	table_decrypted_first_stage = table_decrypt(double_encrypted_text, key3)
	vigenere_decrypted_text = vigenere_decrypt(table_decrypted_first_stage, key2)
	print(f"Double decrypted text with keys '{key2}' and '{key3}': {vigenere_decrypted_text}")


if __name__ == "__main__":
	main()
