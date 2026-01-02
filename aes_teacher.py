# ============================================================
# AES-128 FULL IMPLEMENTATION WITH ENCRYPT & DECRYPT MENU
# ============================================================
#Group Members          ID
# 1.Meronawit Dejene      085
# 2. Hermela Elias        043
# 3. Bisrat Eskeatnaf     063
# ---------------- AES S-BOX -----------------------
# Purpose:
#   The S_BOX (Substitution Box) is used for the SubBytes step in AES.
#   It provides non-linearity and confusion, making AES resistant to
#   linear and differential cryptanalysis.
# How it works:
#   Each byte in the state matrix is replaced by its corresponding value
#   in this 16x16 table. The input byte is split into high nibble (row)
#   and low nibble (column) to index the table.
S_BOX = [
    [99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118],
    [202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192],
    [183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21],
    [4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117],
    [9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132],
    [83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207],
    [208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168],
    [81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210],
    [205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115],
    [96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219],
    [224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121],
    [231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8],
    [186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138],
    [112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158],
    [225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223],
    [140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22]
]

# ---------------- INVERSE S-BOX -------------------
# Purpose:
#   The inverse S_BOX is used in the decryption process (InvSubBytes step).
# How it works:
#   It reverses the byte substitution done during encryption.
INV_S_BOX = [[0]*16 for _ in range(16)]
for i in range(16):
    for j in range(16):
        v = S_BOX[i][j]
        INV_S_BOX[v >> 4][v & 0x0F] = i*16 + j

# ---------------- RCON ----------------------------
# Purpose:
#   RCON (Round Constant) is used in key expansion to provide
#   unique round keys and add non-linearity.
# How it works:
#   Only the first byte of each RCON element is non-zero; it is XORed
#   with the first byte of the transformed word during key expansion.
RCON = [
    [1,0,0,0],[2,0,0,0],[4,0,0,0],[8,0,0,0],
    [16,0,0,0],[32,0,0,0],[64,0,0,0],[128,0,0,0],
    [27,0,0,0],[54,0,0,0]
]

# ---------------- DISPLAY FUNCTION -------------------------
# Purpose:
#   Print the AES state in a human-readable format for debugging.
# How it works:
#   Displays each byte in hexadecimal and as an ASCII character
#   if printable; otherwise, displays a dot.
def print_state(state, title):
    print(title)
    for row in state:
        for b in row:
            ch = chr(b) if 32 <= b <= 126 else '.'
            print(f"{b:02x}({ch})", end="  ")
        print()
    print()

# ---------------- BASIC OPERATIONS -----------------------
# Purpose:
#   XOR, rotate, and substitute words are essential in AES key expansion.

# XOR two 4-byte words
def xor_words(a, b):
    # Purpose: Combine two words using XOR
    # How it works: XOR each corresponding byte
    return [x ^ y for x, y in zip(a, b)]

# Rotate a 4-byte word left by 1 byte
def rot_word(w):
    # Purpose: Rotate word bytes to introduce diffusion
    # How it works: Move first byte to the end
    return w[1:] + w[:1]

# Substitute each byte in a word using S_BOX
def sub_word(w):
    # Purpose: Non-linear byte substitution
    # How it works: Replace each byte using the S_BOX lookup
    return [S_BOX[b >> 4][b & 0x0F] for b in w]

# ---------------- KEY EXPANSION -------------------
# Purpose:
#   Expand the 16-byte key into 44 words (AES-128 uses 10 rounds + 1)
# How it works:
#   - Start with the 4 words of the key
#   - For each new word:
#       * If index is multiple of 4, rotate, substitute, XOR with RCON
#       * XOR with word 4 positions earlier
def key_expansion(key):
    k = [ord(c) for c in key]  # Convert key to byte array
    w = [k[i:i+4] for i in range(0, 16, 4)]

    for i in range(4, 44):
        temp = w[i-1]
        if i % 4 == 0:
            temp = xor_words(sub_word(rot_word(temp)), RCON[i//4 - 1])
        w.append(xor_words(w[i-4], temp))
    return w

# ---------------- STATE OPERATIONS -----------------------
# Purpose:
#   Transformations applied to the 4x4 byte state matrix

# AddRoundKey step: XOR state with round key
def add_round_key(state, rk):
    # Purpose: Mix state with round key
    # How it works: XOR each byte of state with corresponding key byte
    for i in range(4):
        for j in range(4):
            state[i][j] ^= rk[i][j]

# SubBytes step: Substitute each byte using S_BOX
def sub_bytes(state):
    # Purpose: Provide non-linear transformation
    # How it works: Replace each byte using S_BOX
    for i in range(4):
        for j in range(4):
            b = state[i][j]
            state[i][j] = S_BOX[b >> 4][b & 0x0F]

# Inverse SubBytes: Used in decryption
def inv_sub_bytes(state):
    # Purpose: Reverse SubBytes
    # How it works: Replace each byte using INV_S_BOX
    for i in range(4):
        for j in range(4):
            b = state[i][j]
            state[i][j] = INV_S_BOX[b >> 4][b & 0x0F]

# ShiftRows: Cyclically shift each row by its row index
def shift_rows(state):
    # Purpose: Introduce diffusion across columns
    # How it works: Rotate row 1 by 1, row 2 by 2, row 3 by 3
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

# Inverse ShiftRows for decryption
def inv_shift_rows(state):
    # Purpose: Reverse ShiftRows
    # How it works: Rotate row 1 by -1, row 2 by -2, row 3 by -3
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]

# ---------------- MIX COLUMNS ---------------------
# Galois field multiplication for MixColumns
def gmul(a, b):
    # Purpose: Multiply bytes in GF(2^8)
    # How it works: Perform multiplication and reduction by AES polynomial
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

# MixColumns transformation: mix each column using matrix multiplication
def mix_columns(state):
    # Purpose: Provide diffusion in columns
    # How it works: Multiply each column by fixed AES matrix in GF(2^8)
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = gmul(col[0],2)^gmul(col[1],3)^col[2]^col[3]
        state[1][c] = col[0]^gmul(col[1],2)^gmul(col[2],3)^col[3]
        state[2][c] = col[0]^col[1]^gmul(col[2],2)^gmul(col[3],3)
        state[3][c] = gmul(col[0],3)^col[1]^col[2]^gmul(col[3],2)

# Inverse MixColumns for decryption
def inv_mix_columns(state):
    # Purpose: Reverse MixColumns
    # How it works: Multiply each column by inverse AES matrix in GF(2^8)
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = gmul(col[0],14)^gmul(col[1],11)^gmul(col[2],13)^gmul(col[3],9)
        state[1][c] = gmul(col[0],9)^gmul(col[1],14)^gmul(col[2],11)^gmul(col[3],13)
        state[2][c] = gmul(col[0],13)^gmul(col[1],9)^gmul(col[2],14)^gmul(col[3],11)
        state[3][c] = gmul(col[0],11)^gmul(col[1],13)^gmul(col[2],9)^gmul(col[3],14)

# ---------------- AES ENCRYPT ---------------------
# Purpose:
#   Encrypt a 16-byte plaintext block using AES-128
# How it works:
#   - Convert plaintext into 4x4 byte state
#   - Initial AddRoundKey
#   - 9 rounds of SubBytes, ShiftRows, MixColumns, AddRoundKey
#   - Final round: SubBytes, ShiftRows, AddRoundKey
def aes_encrypt(pt, key):
    state = [[ord(pt[r + 4*c]) for c in range(4)] for r in range(4)]
    rk = key_expansion(key)

    print_state(state, "Initial Plaintext State")
    add_round_key(state, [rk[i] for i in range(4)])

    for rnd in range(1,10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, [rk[4*rnd + i] for i in range(4)])
        print_state(state, f"After Round {rnd}")

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, [rk[40+i] for i in range(4)])
    print_state(state, "After Final Round (10)")
    return state

# ---------------- AES DECRYPT ---------------------
# Purpose:
#   Decrypt a 16-byte ciphertext block using AES-128
# How it works:
#   - Initial AddRoundKey with last round key
#   - 9 rounds: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
#   - Final round: InvShiftRows, InvSubBytes, AddRoundKey
def aes_decrypt(cipher, key):
    rk = key_expansion(key)
    state = [row[:] for row in cipher]

    add_round_key(state, [rk[40+i] for i in range(4)])
    inv_shift_rows(state)
    inv_sub_bytes(state)

    for rnd in range(9,0,-1):
        add_round_key(state, [rk[4*rnd + i] for i in range(4)])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    add_round_key(state, [rk[i] for i in range(4)])
    return state

# ================= MENU LOOP ======================
# Purpose:
#   Provide user interface to encrypt or decrypt 16-byte blocks
while True:
    print("\n===== AES-128 MENU =====")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Quit")

    choice = input("Choose option: ").strip()

    if choice == "3":
        print("Goodbye!")
        break

    key = input("Enter 16-character key: ")
    if len(key) != 16:
        print("Key must be 16 characters.")
        continue

    if choice == "1":
        pt = input("Enter 16-character plaintext: ")
        if len(pt) != 16:
            print("Plaintext must be 16 characters.")
            continue

        cipher = aes_encrypt(pt, key)
        print_state(cipher, "Final Ciphertext State")

        hex_out = ''.join(f"{cipher[j][i]:02x}" for i in range(4) for j in range(4))
        print("Ciphertext (hex):", hex_out)

    elif choice == "2":
        hex_in = input("Enter 32 hex-character ciphertext: ")
        if len(hex_in) != 32:
            print("Ciphertext must be 32 hex characters.")
            continue

        bytes_in = [int(hex_in[i:i+2],16) for i in range(0,32,2)]
        cipher = [[bytes_in[r + 4*c] for c in range(4)] for r in range(4)]

        plain = aes_decrypt(cipher, key)
        print_state(plain, "Recovered Plaintext State")

        text = ''.join(chr(plain[j][i]) for i in range(4) for j in range(4))
        print("Recovered Plaintext:", text)

    else: 
        print("Invalid option.")
