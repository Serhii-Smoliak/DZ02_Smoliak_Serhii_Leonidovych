from cryptonita import B
from cryptonita.metrics import icoincidences
from cryptonita.scoring import scoring, key_length_by_ic
from cryptonita.attacks import freq_attack, brute_force
from cryptonita.scoring.freq import etaoin_shrdlu
from cryptonita.fuzzy_set import join_fuzzy_sets, len_join_fuzzy_sets
from cryptonita.scoring import all_ascii_printable
from cryptonita.conv import transpose


def vigenere_encrypt(plaintext, key):
	ptext = B(plaintext)
	secret = B(key)
	ctext = ptext ^ secret.inf()
	return ctext.encode(64)  # Encode as base64 for easier reading


def vigenere_decrypt(ciphertext, key):
	ctext = B(ciphertext, encoding=64)
	secret = B(key)
	ptext = ctext ^ secret.inf()
	return ptext.decode('utf-8')


def find_key_length_kasiski(ciphertext):
	ctext = B(ciphertext, encoding=64)
	# Try different lengths and evaluate IC
	gklength = scoring(
		ctext,
		space=range(5, 25),
		score_func=key_length_by_ic,
		min_score=0.025,
	)
	return gklength.most_likely()


def find_key_length_friedman(ciphertext):
	ctext = B(ciphertext, encoding=64)

	# Calculate IC
	def index_of_coincidence(text):
		return icoincidences(text)

	ic = index_of_coincidence(ctext)
	k = 0.067 / (ic - 0.038) - 1
	return round(k)


def find_key_from_blocks(ciphertext, key_length):
	ctext = B(ciphertext, encoding=64)
	cblocks = ctext.nblocks(key_length)
	cblocks = transpose(cblocks, allow_holes=True)

	most_common_pbytes = etaoin_shrdlu()
	ntop_most_common_cbytes = 1

	gbkeys = []

	for block in cblocks:
		gbkey = freq_attack(block, most_common_pbytes, ntop_most_common_cbytes)
		gbkeys.append(gbkey)

	# Refining guesses
	refined_gbkeys = []
	for i, cblock in enumerate(cblocks):
		refined = brute_force(cblock,
							  score_func=all_ascii_printable,
							  key_space=gbkeys[i],
							  min_score=0.01)
		refined_gbkeys.append(refined)

	# Joining refined guesses
	gkstream = join_fuzzy_sets(refined_gbkeys, cut_off=1024, j=B(''))

	# Getting the most likely key
	kstream = gkstream.most_likely()

	return kstream


def main():
	file_path = "../src/files/input_text.txt"

	with open(file_path, 'r', encoding='utf-8') as file:
		plaintext = file.read()

	key = "CRYPTOGRAPHY"

	encrypted = vigenere_encrypt(plaintext, key)
	decrypted = vigenere_decrypt(encrypted, key)

	print("Encrypted:", encrypted)
	print("Decrypted:", decrypted)

	# Finding key length using Kasiski
	ciphertext = encrypted.decode('utf-8')  # Decode from base64 for analysis
	key_length_kasiski = find_key_length_kasiski(ciphertext)

	print(f"Estimated key length (Kasiski): {key_length_kasiski}")

	# Further analysis to find the key
	key_from_blocks = find_key_from_blocks(ciphertext, key_length_kasiski)
	decrypted_with_found_key = vigenere_decrypt(encrypted, key_from_blocks.decode('utf-8'))

	print("Decrypted with found key:", decrypted_with_found_key)


if __name__ == "__main__":
	main()
