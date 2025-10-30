# Simple key derivation example using python-pkcs11 & nCipher HSMs

# Versions: 
# Security World Software: 13.9
# Firmware: 13.8
# Connect Image 13.9


print("==============================================================")
print("            Proof of Concept: EC Key Derivation               ")
print("==============================================================")
print(" This application demonstrates Elliptic Curve Diffie-Hellman  ")
print(" (ECDH) key exchange and shared AES session key derivation.   ")
print("                                                             ")
print(" Key Features:                                               ")
print(" - Ephemeral EC key pair generation                          ")
print(" - Shared key derivation using ECDH                          ")
print(" - Verification of derived keys                              ")
print("                                                             ")
print(" Note:                                                       ")
print(" * Ensure your HSM supports the required EC curve and KDF.")
print(" * Check asn1crypto for full list of named curves https://github.com/wbond/asn1crypto/blob/master/asn1crypto/keys.py#L338 ")
print(" * Ensure your HSM supports the named curve you choose")
print("==============================================================")

import pkcs11
from pkcs11 import *
from pkcs11.util.ec import encode_named_curve_parameters
import binascii
import getpass

# --- Configuration ---

TOKEN_LABEL = input("Enter your token label (ascii not hexid): ")
USER_PIN = getpass.getpass(prompt="Enter your user pin: ")
CURVE_NAME = input("Enter your EC named-curve (ex: secp256r1): ")
KEY_LENGTH = int(input("Enter your AES key size (128-256): "))

# Define a template to ensure the derived key is readable for verification
# Setting EXTRACTABLE allows us to read the key's value attribute.
EXTRACTABLE_TEMPLATE = {
    Attribute.SENSITIVE: False,
    Attribute.EXTRACTABLE: True,
    Attribute.DERIVE: False,
}

# --- Initialization ---
# Load the PKCS#11 library
# NOTE: This path must be correct for your nCipher setup, change to /opt/nfast/toolkits/pkcs11/libcknfast.so
try:
    lib = pkcs11.lib("C:\\Program Files\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast.dll")
    token = lib.get_token(token_label=TOKEN_LABEL)
except pkcs11.exceptions.LibraryError as e:
    print(f"Error loading PKCS#11 library: {e}")
    # Fallback for demonstration purposes if HSM is not available
    lib = pkcs11.lib()
    try:
        token = lib.create_token(TOKEN_LABEL, USER_PIN)
    except Exception:
        token = lib.get_token(token_label=TOKEN_LABEL) # Assume it exists for fallback

# Pre-calculate the EC domain parameters (required for both parties)
ec_params = encode_named_curve_parameters(CURVE_NAME)

# --- Key Exchange Simulation ---
with token.open(rw=True, user_pin=USER_PIN) as session:

    if session:
        print("")
        print(f"Initalized and opened session with token: '{token.label}' \n") 
    
    # Create EC Domain Parameters object
    ec_parameters = session.create_domain_parameters(KeyType.EC, {
        Attribute.EC_PARAMS: ec_params
    }, local=True)
    

    # --- ALICE'S SIDE ---
    # Alice generates her ephemeral EC key pair
    alice_public, alice_private = ec_parameters.generate_keypair(
         private_template={Attribute.DERIVE: True}
    )
    if alice_public and alice_private:
        print("Successfully generated key pair for Alice")
    else:
        print('Failed to generate key pair for Alice')
        sys.exit(1)
            
    # Get the raw public point value for exchange
    alices_public_point = alice_public[Attribute.EC_POINT] 
    alices_value_hex = binascii.hexlify(alices_public_point).decode()

    print("--- Key Generation ---")
    print(f"Alice's Public EC Point (HEX): {alices_value_hex[:100]}")
    
    # --- BOB'S SIDE ---
    # Bob generates his ephemeral EC key pair
    bobs_public, bobs_private = ec_parameters.generate_keypair(
        private_template={Attribute.DERIVE: True}
    )
    if bobs_public and bobs_private:
        print('Sucessfully generated key pair for Bob')
    else:
        print('Failed to generate key pair for Bob')
        sys.exit(1)
    # Get the raw public point value for exchange
    bobs_public_point = bobs_public[Attribute.EC_POINT]
    bobs_value_hex = binascii.hexlify(bobs_public_point).decode()

    print(f"Bob's Public EC Point (HEX):   {bobs_value_hex[:100]}")
    
    # --- SIMULATE NETWORK EXCHANGE ---
    # Alice receives bobs_public_point
    # Bob receives alices_public_point
    
    # Key Derivation 
    print("\n--- Key Derivation ---")

    # ALICE derives the shared key: (Her Private Key + Bob's Public Point)
    # Mechanism: (KDF.SHA1, None, Partner's Public Key Value)
    alice_session_key = alice_private.derive_key(
        KeyType.AES, KEY_LENGTH,
        mechanism_param=(KDF.SHA512, None, bobs_public_point), # Change KDF to NULL, SHA1, SHA224, SHA256, SHA384, or SHA512
        template=EXTRACTABLE_TEMPLATE # Allows key reading
    )
    
    # BOB derives the shared key: (His Private Key + Alice's Public Point)
    bob_session_key = bobs_private.derive_key(
        KeyType.AES, KEY_LENGTH,
        mechanism_param=(KDF.SHA512, None, alices_public_point), # KDF for BOB must be the same as Alice otherwise it WILL fail!
        template=EXTRACTABLE_TEMPLATE # Allows key reading
    )
    
    #  Verification 
    key_value_alice = alice_session_key[Attribute.VALUE]
    key_value_bob = bob_session_key[Attribute.VALUE]

    
    print(f"Alice's Derived Key (HEX): {binascii.hexlify(key_value_alice).decode()}")
    print(f"Bob's Derived Key (HEX):   {binascii.hexlify(key_value_bob).decode()}")

    if key_value_alice == key_value_bob:
        print("\n **Success:** Both parties derived the identical shared AES session key!")
    else:
        print("\n **Failure:** Keys do not match. Check your HSM's specific KDF and public key format requirements.")