# Initial Permutation Matrix
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Inverse Permutation Matrix
InvP = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

# Permutation made after each SBox substitution
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Initial permutation on key
PC_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# Permutation applied after shifting key (i.e gets Ki+1)
PC_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

# Expand matrix to obtain 48bit matrix
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# SBOX represented as a three dimentional matrix
# --> SBOX[block][row][column]
SBOX = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
     ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
]

# Shift Matrix for each round of keys
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def str_to_bitarray(s):
    # Converts string to a bit array.
    bit_arr = list()
    for byte in s:
        bits = bin(byte)[2:] if isinstance(byte, int) else bin(ord(byte))[2:]
        while len(bits) < 8:
            bits = "0" + bits  # Add additional 0's as needed
        for bit in bits:
            bit_arr.append(int(bit))
    return bit_arr


def bitarray_to_str(bit_arr):
    # Converts bit array to string
    result = ''
    for i in range(0, len(bit_arr), 8):
        byte = bit_arr[i:i + 8]
        s = ''.join([str(b) for b in byte])
        result = result + chr(int(s, 2))
    return result


class DES:
    def __init__(self):
        self.key_text = ""
        self.plain_text = ""
        self.all_keys = []

    @staticmethod
    def left_shift(m_array, round_num):
        num_shift = SHIFT[round_num]
        return m_array[num_shift:] + m_array[:num_shift]

    @staticmethod
    def pc2(m_array):
        keyarray_48bit = []
        for i in range(0, len(PC_2)):
            keyarray_48bit.append(m_array[PC_2[i] - 1])
        return keyarray_48bit

    @staticmethod
    def perms_on_plaintext(m_array, is_inverse_permutation):
        perm_array = IP if is_inverse_permutation is False else InvP
        processed_array = []
        for i in range(0, len(perm_array)):
            processed_array.append(m_array[perm_array[i] - 1])
        return processed_array

    @staticmethod
    def XOR(array_one, array_two):
        # xor function - This function is complete
        return [i ^ j for i, j in zip(array_one, array_two)]

    @staticmethod
    def split_long_text(stuff_to_split, split_at_every):
        return [stuff_to_split[i:i + split_at_every] for i in range(0, len(stuff_to_split), split_at_every)]

    def sbox_substition(self, m_array):
        # Apply sbox subsitution on the bits
        sixbitarrays = self.split_long_text(m_array, 6)

        substresult = []
        s = ""

        for j in range(0, len(sixbitarrays)):
            row = int(str(sixbitarrays[j][0]) + str(sixbitarrays[j][5]), 2)
            col = int(
                str(sixbitarrays[j][1]) + str(sixbitarrays[j][2]) + str(sixbitarrays[j][3]) + str(sixbitarrays[j][4]),
                2)
            sboxintvalue = SBOX[j][row][col]
            s = s + format(sboxintvalue, '04b')  # converts int to bin string

        for c in s:
            substresult.append(int(c))

        return substresult

    def createKeys(self):
        key_bitarray = str_to_bitarray(self.key_text)
        perm_key_bitarray = []
        for i in range(0, len(PC_1)):
            perm_key_bitarray.append(key_bitarray[PC_1[i]])

        key_left = perm_key_bitarray[:28]
        key_right = perm_key_bitarray[28:]

        for i in range(0, 16):
            key_left = self.left_shift(key_left, i)
            key_right = self.left_shift(key_right, i)
            self.all_keys.append(self.pc2(key_left + key_right))

    @staticmethod
    def permute(m_array):
        permuted_array = []
        for i in range(0, len(P)):
            permuted_array.append(m_array[P[i] - 1])
        return permuted_array

    def performRounds(self, m_array, is_encrypt):
        left_part = m_array[:32]
        right_part = m_array[32:]

        if is_encrypt:
            for i in range(0, 16):
                temp_array = right_part
                right_part = self.XOR(left_part, self.performRound(right_part, i))
                left_part = temp_array
            return right_part + left_part
        else:
            for i in range(16, 0, -1):
                temp_array = right_part
                right_part = self.XOR(left_part, self.performRound(right_part, i - 1))
                left_part = temp_array
            return right_part + left_part

    def performRound(self, right_part, round_num):
        # Performs a single round of the DES algorithm
        expanded_array = []
        for i in range(0, len(E)):
            expanded_array.append(right_part[E[i] - 1])

        temp_array = self.XOR(expanded_array, self.all_keys[round_num])
        sboxresult = self.sbox_substition(temp_array)
        return self.permute(sboxresult)

    def encrypt(self, key_text, pln_text):
        self.key_text = key_text
        self.plain_text = pln_text
        self.createKeys()
        s = ""

        katko_array = self.split_long_text(self.plain_text, 8)
        if len(self.plain_text) % 8 != 0:
            katko_array[len(katko_array) - 1] = str(katko_array[len(katko_array) - 1]).ljust(8, " ")
        for i in range(0, len(katko_array)):
            s = s + self.encrypt_main(katko_array[i])
        return s

    def encrypt_main(self, plaintext):
        str_bitarray = str_to_bitarray(plaintext)
        temp_array = self.perms_on_plaintext(str_bitarray, False)
        round_performed_array = self.performRounds(temp_array, True)
        inv_perm_array = self.perms_on_plaintext(round_performed_array, True)
        return bitarray_to_str(inv_perm_array)

    def decrypt(self, encrypted_text, key_text):
        self.key_text = key_text
        self.createKeys()
        s = ""
        katko_array = self.split_long_text(encrypted_text, 8)
        for i in range(0, len(katko_array)):
            s = s + self.decrypt_main(katko_array[i])
        return s.rstrip()

    def decrypt_main(self, enc_text):
        bit_array = str_to_bitarray(enc_text)
        inversed_array = self.perms_on_plaintext(bit_array, False)
        temp_array = self.performRounds(inversed_array, False)
        straight_array = self.perms_on_plaintext(temp_array, True)
        return bitarray_to_str(straight_array)


des = DES()
key = "Awesomee"
plain_text = "##DESAlgorithm##"
print("Plain Text is: " + plain_text)
ciphertext = des.encrypt(key, plain_text)
print("Encrypted Text is: " + ciphertext)
dec_text = des.decrypt(ciphertext, key)
print("Decrypted Text is: " + dec_text)
