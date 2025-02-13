import random
import hashlib

# =====================================
# 1. DIFFIE-HELLMAN PUBLIC PARAMETERS
# =====================================
# 1536-bit prime number from RFC3526 (MODP Group)

p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DDE"
        "F9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E4"
        "85B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE3"
        "86BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007"
        "CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D2"
        "3DCA3AD961C62F356208552BB9ED529077096966D670C354E4"
        "ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)

g = 2  # Standard generator

print("\n=== Diffie-Hellman Public Parameters ===")
print(f"p (RFC3526, 1536 bits) = {p}")
print(f"g = {g}")

# =====================================
# 2. GENERATING PRIVATE KEYS
# =====================================
# Generate random secret keys:
# - a for Alice
# - b for Bob
# - e for Eve (MITM attacker)
a = random.getrandbits(256)
b = random.getrandbits(256)
e = random.getrandbits(256)  # Eve intercepts

print("\n=== Private Keys (Secrets) ===")
print(f"a (Alice) = {a}")
print(f"b (Bob)   = {b}")
print(f"e (Eve)   = {e}")

# =====================================
# 3. MITM ATTACK
# =====================================
# Normally:
#   - Alice sends A = g^a mod p to Bob
#   - Bob sends B = g^b mod p to Alice
#
# But Eve intercepts both messages:
#   - From Alice to Bob (true A)
#   - From Bob to Alice (true B)
# Then replaces them with her own values.

# Original calculations (what Alice and Bob intended to send):
A_real = pow(g, a, p)  # g^a mod p (Alice)
B_real = pow(g, b, p)  # g^b mod p (Bob)

# Eve sends her manipulated values:
M_Eve_B = pow(g, e, p)  # Eve pretends to be Alice to Bob
M_Eve_A = pow(g, e, p)  # Eve pretends to be Bob to Alice

# === Secret keys derived by ALICE and BOB (deceived by Eve) ===
sAlice = pow(M_Eve_A, a, p)  # (g^e)^a mod p
sBob   = pow(M_Eve_B, b, p)  # (g^e)^b mod p

# === Keys obtained by EVE ===
sEve_con_Alice = pow(A_real, e, p)  # (g^a)^e mod p
sEve_con_Bob   = pow(B_real, e, p)  # (g^b)^e mod p

print("\n=== Interception & Manipulation by Eve ===")
print(f"Alice sends (original): A_real = g^a mod p = {A_real}")
print(f"Bob   sends (original): B_real = g^b mod p = {B_real}")
print(f"\nEve intercepts & sends to Bob:   M_Eve_B = g^e mod p = {M_Eve_B}")
print(f"Eve intercepts & sends to Alice: M_Eve_A = g^e mod p = {M_Eve_A}")

print("\n=== Derived Keys (AFTER the attack) ===")
print(f"Alice's key (sAlice)        = (M_Eve_A)^a mod p = {sAlice}")
print(f"Bob's key   (sBob)          = (M_Eve_B)^b mod p = {sBob}")
print(f"Eve's key w/ Alice (sEveA)  = (A_real)^e  mod p = {sEve_con_Alice}")
print(f"Eve's key w/ Bob   (sEveB)  = (B_real)^e  mod p = {sEve_con_Bob}")

# SHA-256 hashing to confirm that:
#   - Alice's key matches Eve's derived key from Alice
#   - Bob's key matches Eve's derived key from Bob
def hash256(x):
    return hashlib.sha256(x.to_bytes(256, byteorder='big')).hexdigest()

hAlice = hash256(sAlice)
hBob   = hash256(sBob)
hEveA  = hash256(sEve_con_Alice)
hEveB  = hash256(sEve_con_Bob)

print("\n=== Hashed Derived Keys (SHA-256) ===")
print(f"Hash(Alice) = {hAlice}")
print(f"Hash(Bob)   = {hBob}")
print(f"Hash(EveA)  = {hEveA}")
print(f"Hash(EveB)  = {hEveB}")

# Key comparison checks:
same_Alice_Eve = (hAlice == hEveA)
same_Bob_Eve   = (hBob == hEveB)
same_Alice_Bob = (hAlice == hBob)

print("\n=== MITM Attack Verification ===")
print(f"Does Alice's key match Eve's key w/ Alice? {same_Alice_Eve}")
print(f"Does Bob's key match Eve's key w/ Bob?   {same_Bob_Eve}")
print(f"Does Alice's key match Bob's key?        {same_Alice_Bob}")

# Expected output in a typical MITM attack:
# * True, True, False
#   => (Alice, EveA) share a key
#   => (Bob, EveB) share a different key
#   => Alice and Bob DO NOT share the same key
