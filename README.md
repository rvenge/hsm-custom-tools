Collection of custom tools geared towards **nCipher Hardware Security Modules (HSM)**, but generally compatible with other HSM libraries (like those implementing PKCS#11) using languages such as **Python, C++, and C#**.

This repository serves as a sandbox for implementing custom or non-standard cryptographic operations within an HSM environment.

***

## 🚀 Key Tools and Features

This repository contains various tools demonstrating custom HSM operations across different programming languages.

| File | Language | Description | Key Operation |
| :--- | :--- | :--- | :--- |
| `ecdh_derive.py` | Python | A Python tool for **Elliptic Curve Diffie-Hellman (ECDH)** key derivation. | **Key Derivation** |
| `gen_ec_key.cs` | C# | A C# utility for generating ephemeral **Elliptic Curve (EC)** key pairs inside the HSM. | **Key Generation** |
| `mldsa_keygen.cpp` | C++ | A C++ tool for generating **ML-DSA (CRYSTALS-Dilithium)** key pairs. *ML-DSA is a FIPS-standardized post-quantum signature algorithm.* | **Post-Quantum Key Generation** |
| `mldsa_integrity.cpp` | C++ | A C++ tool for signing & verifying the integrity of **ML-DSA** signatures. | **Signature & Verification** |

***

## 🛠️ Prerequisites

To build and run these tools, you will need the following:

1.  **A Working Hardware Security Module (HSM) Setup:** This includes the physical HSM device, necessary drivers, and a configured security world.
2.  **HSM SDK/Libraries:** Access to the specific SDK (e.g., nShield Security World Software) and associated cryptographic libraries (like `nShield` libraries or a generic **PKCS#11** library).
3.  **Development Environment:**
    * **C++:** A C++ compiler (e.g., GCC, MSVC) compatible with your HSM SDK headers.
    * **Python:** A Python 3 interpreter and any required third-party libraries (check the script for dependencies).
    * **C#:** The .NET framework or .NET SDK for compiling and running C# applications.

***

## ⚙️ Installation and Setup

### 1. Clone the Repository

```bash
git clone [https://github.com/rvenge/hsm-custom-tools.git](https://github.com/rvenge/hsm-custom-tools.git)
cd hsm-custom-tools
```
### 2. Configure HSM Environment

Ensure your HSM environment variables (e.g., NFAST_HOME, PKCS#11 library path) are correctly set up and that you can access the HSM via standard tools before attempting to use these custom tools.

### 3. Build C++ and C# Tools

The C++ (.cpp) and C# (.cs) files must be compiled before they can be used. You will need to link against the necessary HSM libraries provided by your vendor's SDK.

For C++ tools (.cpp):
```
g++ mldsa_keygen.cpp -o mldsa_keygen.exe -I<HSM_HEADER_INCLUDE_PATH> -L<HSM_PKCS11_LIB_PATH> -l<HSM_LIB_NAME>
```

Example (will vary based on OS/SDK path)
```
g++ mldsa_keygen.cpp -o mldsa_keygen -I<HSM_SDK_INCLUDE_PATH> -L<HSM_SDK_LIB_PATH> -l<HSM_LIB_NAME>
```
For C# tools (.cs):
```
# Use the .NET build system
How to build C# projects

Download .NET SDK if you have not already https://dotnet.microsoft.com/en-us/download


1. Add PKCS11Interop Package 

dotnet add package Pkcs11Interop

Build succeeded in 5.0s
info : X.509 certificate chain validation will use the default trust store selected by .NET for code signing.
info : X.509 certificate chain validation will use the default trust store selected by .NET for timestamping.
info : Adding PackageReference for package 'Pkcs11Interop' into project 'C:\Users\admin\MyApp\MyApp.csproj'.
info :   GET https://api.nuget.org/v3/registration5-gz-semver2/pkcs11interop/index.json
info :   OK https://api.nuget.org/v3/registration5-gz-semver2/pkcs11interop/index.json 421ms
info : Restoring packages for C:\Users\admin\MyApp\MyApp.csproj...
info :   GET https://api.nuget.org/v3-flatcontainer/pkcs11interop/index.json
info :   OK https://api.nuget.org/v3-flatcontainer/pkcs11interop/index.json 113ms
info :   GET https://api.nuget.org/v3-flatcontainer/pkcs11interop/5.3.0/pkcs11interop.5.3.0.nupkg
info :   OK https://api.nuget.org/v3-flatcontainer/pkcs11interop/5.3.0/pkcs11interop.5.3.0.nupkg 81ms
info : Installed Pkcs11Interop 5.3.0 from https://api.nuget.org/v3/index.json to C:\Users\admin\.nuget\packages\pkcs11interop\5.3.0 with content hash NnnD5CheO5d0ZTP/clt7XCjUy+FraxZv0hVP0GWSvry8jH4IrLifta04M9cjITr0EzKshG4qnFu2pdZZfhjttA==.
info :   GET https://api.nuget.org/v3/vulnerabilities/index.json
info :   OK https://api.nuget.org/v3/vulnerabilities/index.json 18ms
info :   GET https://api.nuget.org/v3-vulnerabilities/2025.07.31.17.40.39/vulnerability.base.json
info :   GET https://api.nuget.org/v3-vulnerabilities/2025.07.31.17.40.39/2025.08.06.11.41.03/vulnerability.update.json
info :   OK https://api.nuget.org/v3-vulnerabilities/2025.07.31.17.40.39/vulnerability.base.json 42ms
info :   OK https://api.nuget.org/v3-vulnerabilities/2025.07.31.17.40.39/2025.08.06.11.41.03/vulnerability.update.json 70ms
info : Package 'Pkcs11Interop' is compatible with all the specified frameworks in project 'C:\Users\admin\MyApp\MyApp.csproj'.
info : PackageReference for package 'Pkcs11Interop' version '5.3.0' added to file 'C:\Users\admin\MyApp\MyApp.csproj'.
info : Writing assets file to disk. Path: C:\Users\admin\MyApp\obj\project.assets.json
log  : Restored C:\Users\admin\MyApp\MyApp.csproj (in 2.45 sec).

# Create Project Directory 

C:\Users\admin> dotnet new console -o MyApp
The template "Console App" was created successfully.

Processing post-creation actions...
Restoring C:\Users\admin\MyApp\MyApp.csproj:
Restore succeeded.

# Change directory to Project

C:\Users\admin> cd .\MyApp\
C:\Users\admin\MyApp> ls


    Directory: C:\Users\admin\MyApp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          8/6/2025  10:49 AM                obj
-a----          8/6/2025  10:49 AM            252 MyApp.csproj
-a----          8/6/2025  10:49 AM            105 Program.cs


2. Insert your code to Program.cs

3. Build the program 
C:\Users\admin\MyApp> dotnet build
Restore complete (0.5s)
  MyApp succeeded (2.8s) → bin\Debug\net9.0\MyApp.dll

Build succeeded in 4.0s

4. Run the program 
C:\Users\admin\MyApp> dotnet run

Private key value (d): C2914A08D82D55F110A825053E97651C24AEA3C0FFB587176AEB6C30AE292BC7

Private Key created successfully.

Key attributes:
Key label: TestKey
Key class: CKO_PRIVATE_KEY
Key type: CKK_EC
Curve ID: 06-08-2A-86-48-CE-3D-03-01-07
Sensitive: True
Sign: True
Derive: True
Extractable: False
Wrap with trusted: True
```

▶️ Usage Examples

The usage for each tool depends on its specific implementation details (command-line arguments, required configuration files).

Python Example (ecdh_derive.py)

Run the script using the Python interpreter.
```
python ecdh_derive.py 
```
C++ Example (mldsa_keygen)

Run the compiled executable from your terminal.

```
./mldsa_keygen.exe <parameter_set> <key_label> [public_key_export_file]

Parameter sets:
  44  - ML-DSA-44 (NIST Level 2, 128-bit security)
  65  - ML-DSA-65 (NIST Level 3, 192-bit security)
  87  - ML-DSA-87 (NIST Level 5, 256-bit security)

Examples:
  C:\Users\admin\Desktop\Projects\testing\C++\pkcs11\testing\pqcrypto\mldsa_keygen_utility.exe 87 "MyAppSigning" exported_public.raw
  C:\Users\admin\Desktop\Projects\testing\C++\pkcs11\testing\pqcrypto\mldsa_keygen_utility.exe 65 "CodeSigning-2025"
```

    
