// mldsa_integrity.cpp
// ML-DSA Signer using PKCS#11
// Integrity tool to sign and verify ML-DSA signatures. 
// Requires 13.9 nShield software & firmware

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <map>
#include <algorithm>
#include <cctype>
#include <fstream>

// Windows-specific includes
#ifdef _WIN32
    #define NOMINMAX
    #include <windows.h>
    #pragma pack(push, cryptoki, 1)
    #define CK_PTR *
    #define CK_DECLARE_FUNCTION(returnType, name) returnType name
    #define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
    #define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
    #ifndef NULL_PTR
        #define NULL_PTR 0
    #endif
#endif

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11extra.h" // Found in nShield 13.9 software in C:\Program Files\nCipher\nfast\c\ctd\vs2022-64\include or /opt/nfast/c/ctd/vs2022-64/include

#ifdef _WIN32
    #pragma pack(pop, cryptoki)
#endif

// ML-DSA mechanism constants (PKCS#11 v3.2)
#ifndef CKM_ML_DSA_KEY_PAIR_GEN
    #define CKM_ML_DSA_KEY_PAIR_GEN        0x00000005UL
#endif
#ifndef CKM_ML_DSA
    #define CKM_ML_DSA                     0x00000006UL
#endif

// ML-DSA parameter sets
#ifndef CKK_ML_DSA
    #define CKK_ML_DSA                     0x00000035UL
#endif

// ML-DSA parameter set values (nCipher specific)
#ifndef CKP_ML_DSA_44
    #define CKP_ML_DSA_44                  0x00000001UL
#endif
#ifndef CKP_ML_DSA_65
    #define CKP_ML_DSA_65                  0x00000002UL
#endif
#ifndef CKP_ML_DSA_87
    #define CKP_ML_DSA_87                  0x00000003UL
#endif

// Command line options structure
struct CommandLineOptions {
    std::string keyLabel;
    std::string inputFile;
    std::string outputFile;
    std::string signatureFile;
    int slotIndex;
    bool showHelp;
    bool signMode;
    bool verifyMode;
    
    CommandLineOptions() : slotIndex(0), showHelp(false), signMode(false), verifyMode(false) {}
};

// Function declarations
void printHelp(const std::string& programName);
CommandLineOptions parseCommandLine(int argc, char* argv[]);
bool isValidSlotIndex(int slotIndex);
bool openSession(int slotIndex);
bool findPrivateKey(const std::string& keyLabel, CK_OBJECT_HANDLE& hPrivateKey);
bool findPublicKey(const std::string& keyLabel, CK_OBJECT_HANDLE& hPublicKey);
bool signFile(const std::string& inputFile, const std::string& outputFile, const std::string& keyLabel);
bool verifySignature(const std::string& inputFile, const std::string& signatureFile, const std::string& keyLabel);
bool performSignatureTest(const std::string& keyLabel);


// Error handling macro
#define CHECK_RV(rv, msg) \
    if (rv != CKR_OK) { \
        std::cerr << "Error: " << msg << " - Return code: 0x" << std::hex << rv << std::endl; \
        cleanup(); \
        return false; \
    }

// Global variables
CK_FUNCTION_LIST_PTR pFunctionList = NULL;
CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
bool libraryInitialized = false;

void cleanup() {
    if (hSession != CK_INVALID_HANDLE) {
        pFunctionList->C_CloseSession(hSession);
        hSession = CK_INVALID_HANDLE;
    }
    if (libraryInitialized && pFunctionList) {
        pFunctionList->C_Finalize(NULL_PTR);
        libraryInitialized = false;
    }
}

// ML-DSA parameter set information
struct MLDSAParameterSet {
    CK_ULONG parameterSet;
    std::string name;
    std::string description;
    int nistLevel;
    int expectedPublicKeySize;
    int expectedSignatureSize;
    std::string securityEquivalent;
};

std::vector<MLDSAParameterSet> getMLDSAParameterSets() {
    return {
        {CKP_ML_DSA_44, "ML-DSA-44", "Fast, compact signatures", 2, 1312, 2420, "AES-128"},
        {CKP_ML_DSA_65, "ML-DSA-65", "Balanced performance", 3, 1952, 3309, "AES-192"},
        {CKP_ML_DSA_87, "ML-DSA-87", "Maximum security", 5, 2592, 4627, "AES-256"}
    };
}

bool initializePKCS11() {    
    std::cout << "\n=================================================================" << std::endl;
    std::cout << "PKCS#11 ML-DSA Key Integrity Tool (64-bit)" << std::endl;
    std::cout << "=================================================================" << std::endl;

    // Get PKCS#11 function list
    CK_C_GetFunctionList pGetFunctionList = NULL;
    CK_RV rv;

    #ifdef _WIN32
        HMODULE hModule = LoadLibraryA("cknfast.dll"); // found in C:\Program Files\nCipher\nfast\toolkits\pkcs11\cknfast.dll or /opt/nfast/toolkits/pkcs11/libcknfast.so
        if (!hModule) {
            std::cerr << "Failed to load PKCS#11 library (cknfast.dll)" << std::endl;
            return false;
        }
        pGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hModule, "C_GetFunctionList");
    #endif

    if (!pGetFunctionList) {
        std::cerr << "Failed to get C_GetFunctionList" << std::endl;
        return false;
    }

    rv = pGetFunctionList(&pFunctionList);
    CHECK_RV(rv, "C_GetFunctionList failed");

    // Initialize Cryptoki
    rv = pFunctionList->C_Initialize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        std::cerr << "C_Initialize failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
    libraryInitialized = true;
    std::cout << "PKCS#11 library initialized successfully" << std::endl;

    // Get library info
    CK_INFO info;
    rv = pFunctionList->C_GetInfo(&info);
    CHECK_RV(rv, "C_GetInfo failed");

    std::cout << "Library: " << std::string((char*)info.libraryDescription, 32) << std::endl;
    std::cout << "Version: " << (int)info.libraryVersion.major << "." << (int)info.libraryVersion.minor << std::endl;

    return true;
}

bool openSession(int slotIndex) {
    CK_RV rv;
    CK_ULONG slotCount;
    
    // Get slot list
    rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount);
    CHECK_RV(rv, "C_GetSlotList failed");

    if (slotCount == 0) {
        std::cerr << "No slots with tokens found" << std::endl;
        return false;
    }

    std::vector<CK_SLOT_ID> slots(slotCount);
    rv = pFunctionList->C_GetSlotList(CK_TRUE, slots.data(), &slotCount);
    CHECK_RV(rv, "C_GetSlotList failed");

    std::cout << "Found " << slotCount << " slot(s) with tokens" << std::endl;
    
    // Validate requested slot index
    if (slotIndex >= static_cast<int>(slotCount)) {
        std::cerr << "Error: Requested slot index " << slotIndex << " not available. ";
        std::cerr << "Available slots: 0 to " << (slotCount - 1) << std::endl;
        return false;
    }
    
    std::cout << "Using slot index: " << slotIndex << " (slot ID: " << slots[slotIndex] << ")" << std::endl;

    // Open session
    rv = pFunctionList->C_OpenSession(slots[slotIndex], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
    CHECK_RV(rv, "C_OpenSession failed");

    std::cout << "Read-write session opened successfully" << std::endl;
    return true;
}

void printHelp(const std::string& programName) {
    std::cout << "ML-DSA Quantum Ready Integrity Tool" << std::endl;
    std::cout << "====================================" << std::endl;
    std::cout << "Usage: " << programName << " [OPTIONS]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help                    Show this help message" << std::endl;
    std::cout << "  -l, --label <label>           Key label to use from HSM" << std::endl;
    std::cout << "  -s, --slot <index>            HSM slot index (default: 0)" << std::endl;
    std::cout << "  --sign <file>                 Sign a file using private key from HSM" << std::endl;
    std::cout << "  -v, --verify                  Verify a signature" << std::endl;
    std::cout << "  -f, --file <file>             Input file to sign or verify" << std::endl;
    std::cout << "  -o, --output <file>           Output file for signature (default: <input>.sig)" << std::endl;
    std::cout << "  --sig <file>                  Signature file for verification" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  Sign a file:" << std::endl;
    std::cout << "    " << programName << " --sign -l MyPrivateKey -f document.pdf -o document.sig" << std::endl;
    std::cout << std::endl;
    std::cout << "  Verify with HSM public key:" << std::endl;
    std::cout << "    " << programName << " -v -l MyPublicKey -f document.pdf --sig document.sig" << std::endl;
    std::cout << std::endl;
    std::cout << "Note: If no file is provided for signing, a test signature will be performed." << std::endl;
    std::cout << "Note: For external public key verification, use OpenSSL 3.5 directly." << std::endl;
}

CommandLineOptions parseCommandLine(int argc, char* argv[]) {
    CommandLineOptions options;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            options.showHelp = true;
            return options;
        }
        else if (arg == "-l" || arg == "--label") {
            if (i + 1 < argc) {
                options.keyLabel = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                options.showHelp = true;
                return options;
            }
        }
        else if (arg == "-s" || arg == "--slot") {
            if (i + 1 < argc) {
                try {
                    int slotIndex = std::stoi(argv[++i]);
                    if (isValidSlotIndex(slotIndex)) {
                        options.slotIndex = slotIndex;
                    } else {
                        std::cerr << "Error: Invalid slot index '" << slotIndex << "'" << std::endl;
                        options.showHelp = true;
                        return options;
                    }
                } catch (const std::exception&) {
                    std::cerr << "Error: Invalid slot index format '" << argv[i] << "'" << std::endl;
                    options.showHelp = true;
                    return options;
                }
            } else {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                options.showHelp = true;
                return options;
            }
        }
        else if (arg == "--sign") {
            options.signMode = true;
        }
        else if (arg == "-v" || arg == "--verify") {
            options.verifyMode = true;
        }
        else if (arg == "-f" || arg == "--file") {
            if (i + 1 < argc) {
                options.inputFile = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                options.showHelp = true;
                return options;
            }
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                options.outputFile = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                options.showHelp = true;
                return options;
            }
        }
        else if (arg == "--sig") {
            if (i + 1 < argc) {
                options.signatureFile = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                options.showHelp = true;
                return options;
            }
        }
        else {
            std::cerr << "Error: Unknown option '" << arg << "'" << std::endl;
            options.showHelp = true;
            return options;
        }
    }
    
    return options;
}

bool isValidSlotIndex(int slotIndex) {
    return slotIndex >= 0 && slotIndex <= 20;
}

bool findPrivateKey(const std::string& keyLabel, CK_OBJECT_HANDLE& hPrivateKey) {
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_ML_DSA;
    
    CK_ATTRIBUTE searchTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (CK_VOID_PTR)keyLabel.c_str(), static_cast<CK_ULONG>(keyLabel.size())}
    };
    
    rv = pFunctionList->C_FindObjectsInit(hSession, searchTemplate, sizeof(searchTemplate)/sizeof(searchTemplate[0]));
    if (rv != CKR_OK) {
        std::cerr << "C_FindObjectsInit failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
    
    CK_ULONG objectCount;
    rv = pFunctionList->C_FindObjects(hSession, &hPrivateKey, 1, &objectCount);
    pFunctionList->C_FindObjectsFinal(hSession);
    
    if (rv != CKR_OK || objectCount == 0) {
        std::cerr << "Private key with label '" << keyLabel << "' not found" << std::endl;
        return false;
    }
    
    std::cout << "\nFound private key with label: " << keyLabel << std::endl;
    return true;
}

bool findPublicKey(const std::string& keyLabel, CK_OBJECT_HANDLE& hPublicKey) {
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_ML_DSA;
    
    CK_ATTRIBUTE searchTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (CK_VOID_PTR)keyLabel.c_str(), static_cast<CK_ULONG>(keyLabel.size())}
    };
    
    rv = pFunctionList->C_FindObjectsInit(hSession, searchTemplate, sizeof(searchTemplate)/sizeof(searchTemplate[0]));
    if (rv != CKR_OK) {
        std::cerr << "C_FindObjectsInit failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
    
    CK_ULONG objectCount;
    rv = pFunctionList->C_FindObjects(hSession, &hPublicKey, 1, &objectCount);
    pFunctionList->C_FindObjectsFinal(hSession);
    
    if (rv != CKR_OK || objectCount == 0) {
        std::cerr << "Public key with label '" << keyLabel << "' not found" << std::endl;
        return false;
    }
    
    std::cout << "Found public key with label: " << keyLabel << std::endl;
    return true;
}

// Note: External public key verification is not supported.
// Use OpenSSL 3.5 for external verification operations.

bool signFile(const std::string& inputFile, const std::string& outputFile, const std::string& keyLabel) {
    CK_RV rv;
    CK_OBJECT_HANDLE hPrivateKey;
    
    // Find the private key
    if (!findPrivateKey(keyLabel, hPrivateKey)) {
        return false;
    }
    
    // Read the input file
    std::ifstream file(inputFile, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open input file: " << inputFile << std::endl;
        return false;
    }
    
    // Read file contents
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<CK_BYTE> fileData(fileSize);
    file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
    file.close();
    
    std::cout << "Read " << fileSize << " bytes from file: " << inputFile << std::endl;
    
    // Sign the data
    CK_MECHANISM signMechanism = {CKM_ML_DSA, NULL_PTR, 0};
    rv = pFunctionList->C_SignInit(hSession, &signMechanism, hPrivateKey);
    if (rv != CKR_OK) {
        std::cerr << "C_SignInit failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
     
    // Get signature length
    CK_ULONG signatureLen = 0;
    auto signStart = std::chrono::high_resolution_clock::now();
    rv = pFunctionList->C_Sign(hSession, fileData.data(), static_cast<CK_ULONG>(fileData.size()), NULL_PTR, &signatureLen);
    if (rv != CKR_OK) {
        std::cerr << "C_Sign (get length) failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
    
    // Create signature
    std::vector<CK_BYTE> signature(signatureLen);
    rv = pFunctionList->C_Sign(hSession, fileData.data(), static_cast<CK_ULONG>(fileData.size()), signature.data(), &signatureLen);
    auto signEnd = std::chrono::high_resolution_clock::now();
    
    if (rv != CKR_OK) {
        std::cerr << "C_Sign failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
    
    auto signTime = std::chrono::duration_cast<std::chrono::milliseconds>(signEnd - signStart);
    
    // Write signature to file
    std::ofstream sigFile(outputFile, std::ios::binary);
    if (!sigFile) {
        std::cerr << "Failed to create signature file: " << outputFile << std::endl;
        return false;
    }
    
    sigFile.write(reinterpret_cast<const char*>(signature.data()), signatureLen);
    sigFile.close();
    
    std::cout << "\n============================================================" << std::endl;
    std::cout << "SUCCESS: File signed successfully!" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << "  Input file:     " << inputFile << " (" << fileSize << " bytes)" << std::endl;
    std::cout << "  Signature file: " << outputFile << " (" << signatureLen << " bytes)" << std::endl;
    std::cout << "  Signing time:   " << signTime.count() << " ms" << std::endl;
    std::cout << "============================================================" << std::endl;
    
    return true;
}

bool verifySignature(const std::string& inputFile, const std::string& signatureFile, const std::string& keyLabel) {
    CK_RV rv;
    CK_OBJECT_HANDLE hPublicKey;
    
    // Find public key in HSM
    if (!findPublicKey(keyLabel, hPublicKey)) {
        return false;
    }
    
    // Read the input file
    std::ifstream file(inputFile, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open input file: " << inputFile << std::endl;
        return false;
    }
    
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<CK_BYTE> fileData(fileSize);
    file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
    file.close();
    
    // Read the signature file
    std::ifstream sigFile(signatureFile, std::ios::binary);
    if (!sigFile) {
        std::cerr << "Failed to open signature file: " << signatureFile << std::endl;
        return false;
    }
    
    sigFile.seekg(0, std::ios::end);
    size_t sigSize = sigFile.tellg();
    sigFile.seekg(0, std::ios::beg);
    
    std::vector<CK_BYTE> signature(sigSize);
    sigFile.read(reinterpret_cast<char*>(signature.data()), sigSize);
    sigFile.close();
    
    std::cout << "Read " << fileSize << " bytes from input file: " << inputFile << std::endl;
    std::cout << "Read " << sigSize << " bytes from signature file: " << signatureFile << std::endl;
    
    // Verify the signature
    CK_MECHANISM verifyMechanism = {CKM_ML_DSA, NULL_PTR, 0};
    rv = pFunctionList->C_VerifyInit(hSession, &verifyMechanism, hPublicKey);
    if (rv != CKR_OK) {
        std::cerr << "C_VerifyInit failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
    
    auto verifyStart = std::chrono::high_resolution_clock::now();
    rv = pFunctionList->C_Verify(hSession, fileData.data(), static_cast<CK_ULONG>(fileData.size()), signature.data(), static_cast<CK_ULONG>(signature.size()));
    auto verifyEnd = std::chrono::high_resolution_clock::now();
    auto verifyTime = std::chrono::duration_cast<std::chrono::milliseconds>(verifyEnd - verifyStart);
    
    if (rv == CKR_OK) {
        std::cout << "\n============================================================" << std::endl;
        std::cout << "SUCCESS: Signature verification successful!" << std::endl;
        std::cout << "============================================================" << std::endl;
        std::cout << "  Verification time: " << verifyTime.count() << " ms" << std::endl;
        std::cout << "============================================================" << std::endl;
        return true;
    } else if (rv == CKR_SIGNATURE_INVALID) {
        std::cout << "\n============================================================" << std::endl;
        std::cout << "FAILED: Signature is invalid!" << std::endl;
        std::cout << "============================================================" << std::endl;
        return false;
    } else {
        std::cerr << "\n============================================================" << std::endl;
        std::cerr << "FAILED: Signature verification failed: 0x" << std::hex << rv << std::endl;
        std::cerr << "============================================================" << std::endl;
        return false;
    }
}

bool performSignatureTest(const std::string& keyLabel) {
    std::cout << "\n=== ML-DSA Signature Test ===" << std::endl;
    
    CK_RV rv;
    CK_OBJECT_HANDLE hPrivateKey, hPublicKey;
    
    // Find keys
    if (!findPrivateKey(keyLabel, hPrivateKey)) {
        return false;
    }
    
    // Try to find corresponding public key
    std::string pubKeyLabel = keyLabel;
    
    if (!findPublicKey(pubKeyLabel, hPublicKey)) {
        std::cerr << "Warning: Could not find corresponding public key" << std::endl;
        return false;
    }
    
    // Create test data
    std::string testMessage = "ML-DSA Post-Quantum Digital Signature Test - This message demonstrates quantum-resistant cryptography using ML-DSA (FIPS 204)";
    std::vector<CK_BYTE> testData(testMessage.begin(), testMessage.end());
    
    std::cout << "Test message: \"" << testMessage << "\"" << std::endl;
    std::cout << "Message length: " << testData.size() << " bytes" << std::endl;
    
    // Sign the data
    CK_MECHANISM signMechanism = {CKM_ML_DSA, NULL_PTR, 0};
    rv = pFunctionList->C_SignInit(hSession, &signMechanism, hPrivateKey);
    if (rv != CKR_OK) {
        std::cerr << "C_SignInit failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
    
    CK_ULONG signatureLen = 0;
    auto signStart = std::chrono::high_resolution_clock::now();
    rv = pFunctionList->C_Sign(hSession, testData.data(), static_cast<CK_ULONG>(testData.size()), NULL_PTR, &signatureLen);
    if (rv != CKR_OK) {
        std::cerr << "C_Sign (get length) failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
    
    std::vector<CK_BYTE> signature(signatureLen);
    rv = pFunctionList->C_Sign(hSession, testData.data(), static_cast<CK_ULONG>(testData.size()), signature.data(), &signatureLen);
    auto signEnd = std::chrono::high_resolution_clock::now();
    
    if (rv != CKR_OK) {
        std::cerr << "C_Sign failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
    
    auto signTime = std::chrono::duration_cast<std::chrono::milliseconds>(signEnd - signStart);
    std::cout << "SUCCESS: Test message signed successfully!" << std::endl;
    std::cout << "  Signature size: " << signatureLen << " bytes" << std::endl;
    std::cout << "  Signing time: " << signTime.count() << " ms" << std::endl;
    
    // Verify the signature
    std::cout << "\n=== Signature Verification ===" << std::endl;
    rv = pFunctionList->C_VerifyInit(hSession, &signMechanism, hPublicKey);
    if (rv != CKR_OK) {
        std::cerr << "C_VerifyInit failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
    
    auto verifyStart = std::chrono::high_resolution_clock::now();
    rv = pFunctionList->C_Verify(hSession, testData.data(), static_cast<CK_ULONG>(testData.size()), signature.data(), signatureLen);
    auto verifyEnd = std::chrono::high_resolution_clock::now();
    auto verifyTime = std::chrono::duration_cast<std::chrono::milliseconds>(verifyEnd - verifyStart);
    
    if (rv == CKR_OK) {
        std::cout << "SUCCESS: Test signature verification successful!" << std::endl;
        std::cout << "  Verification time: " << verifyTime.count() << " ms" << std::endl;
        return true;
    } else {
        std::cerr << "FAILED: Test signature verification failed: 0x" << std::hex << rv << std::endl;
        return false;
    }
}
int main(int argc, char* argv[]) {
    // Parse command line arguments
    CommandLineOptions options = parseCommandLine(argc, argv);
    
    if (options.showHelp) {
        printHelp(argv[0]);
        return 0;
    }
    
    // Validate basic requirements
    if (!options.signMode && !options.verifyMode) {
        std::cerr << "Error: Must specify either --sign or --verify mode" << std::endl;
        printHelp(argv[0]);
        return 1;
    }
    
    if (options.signMode && options.verifyMode) {
        std::cerr << "Error: Cannot specify both --sign and --verify modes" << std::endl;
        return 1;
    }
    
    if (options.keyLabel.empty()) {
        std::cerr << "Error: Must specify --label for HSM key" << std::endl;
        return 1;
    }
    
    // Initialize PKCS#11
    if (!initializePKCS11()) {
        return 1;
    }
    
    if (!openSession(options.slotIndex)) {
        cleanup();
        return 1;
    }
    
    bool success = false;
    
    if (options.signMode) {
        if (options.inputFile.empty()) {
            // No file provided, ask user if they want a test run
            std::cout << "Warning: File not provided. Would you like to proceed with a signature test run? (y/n): ";
            std::string response;
            std::getline(std::cin, response);
            
            if (response == "y" || response == "Y" || response == "yes" || response == "YES") {
                success = performSignatureTest(options.keyLabel);
            } else {
                std::cout << "Please provide a proper file name using -f or --file option." << std::endl;
                cleanup();
                return 1;
            }
        } else {
            // Sign the specified file
            std::string outputFile = options.outputFile;
            if (outputFile.empty()) {
                outputFile = options.inputFile + ".sig";
            }
            success = signFile(options.inputFile, outputFile, options.keyLabel);
        }
    }
    else if (options.verifyMode) {
        if (options.inputFile.empty() || options.signatureFile.empty()) {
            std::cerr << "Error: Verification requires both input file (-f) and signature file (--sig)" << std::endl;
            cleanup();
            return 1;
        }
        
        success = verifySignature(options.inputFile, options.signatureFile, options.keyLabel);
    }
    
    cleanup();
    
    if (success) {
        std::cout << "\nOperation completed successfully!" << std::endl;
        return 0;
    } else {
        std::cout << "\nOperation failed!" << std::endl;
        return 1;
    }
}
