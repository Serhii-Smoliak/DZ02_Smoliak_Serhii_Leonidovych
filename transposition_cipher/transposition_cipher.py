import math
import os


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


def double_transposition_encrypt(text, key1, key2):
	# First stage: Encrypt using the first key
	encrypted_first_stage = table_encrypt(text, key1)

	# Second stage: Encrypt the result using the second key
	encrypted_second_stage = table_encrypt(encrypted_first_stage, key2)

	return encrypted_second_stage


def double_transposition_decrypt(cipher_text, key1, key2):
	# First stage: Decrypt using the second key
	decrypted_first_stage = table_decrypt(cipher_text, key2)

	# Second stage: Decrypt the result using the first key
	decrypted_second_stage = table_decrypt(decrypted_first_stage, key1)

	return decrypted_second_stage.strip()


def main():
	base_dir = "../src/files"
	input_filename = os.path.join(base_dir, 'input_text.txt')

	# Read text from file
	with open(input_filename, 'r', encoding='utf-8') as file:
		text = file.read()

	# Level 1: Encryption and decryption with key "SECRET"
	key1 = "SECRET"

	encrypted_text_secret = table_encrypt(text, key1)
	print(f"Encrypted text with key '{key1}': {encrypted_text_secret}")

	decrypted_text_secret = table_decrypt(encrypted_text_secret, key1)
	print(f"Decrypted text with key '{key1}': {decrypted_text_secret}")

	# Level 2: Double transposition with keys "SECRET" and "CRYPTO"
	key2 = "CRYPTO"

	double_encrypted_text = double_transposition_encrypt(text, key1, key2)
	print(f"Double encrypted text with keys '{key1}' and '{key2}': {double_encrypted_text}")

	double_decrypted_text = double_transposition_decrypt(double_encrypted_text, key1, key2)
	print(f"Double decrypted text with keys '{key1}' and '{key2}': {double_decrypted_text}")


if __name__ == "__main__":
	main()
