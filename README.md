***ec_derive_poc.py*** 

This application demonstrates ECDH key exchange and shared AES key derivation. Allows for flexible slot, pin, curve, and AES key size selection. Generates two EC keys; EC public points are shared between parties. These points are used by the other party to generate an identical derived AES key from the original key pair. Serves as a starting point for devs to explore KDF using PKCS#11 and HSMs. 

<img width="953" height="483" alt="image" src="https://github.com/user-attachments/assets/861c6538-1a64-4544-aa52-3894b51d03f2" />
