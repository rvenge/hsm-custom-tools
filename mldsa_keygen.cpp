// Sample program to generate keys using nCipher HSM 
// Requires 13.9 software and firmware 
// OpenSSL 3.5 for external usage with the public key. 

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
    std::vector<std::string> parameterSets;
    std::string keyLabel;
    int slotIndex;
    bool showHelp;
    bool extractPublicKey;
    
    CommandLineOptions() : keyLabel("MLDSA-KeyPair"), slotIndex(0), showHelp(false), extractPublicKey(false) {}
};

// Function declarations
void printHelp(const std::string& programName);
CommandLineOptions parseCommandLine(int argc, char* argv[]);
bool isValidParameterSet(const std::string& paramSet);
bool isValidSlotIndex(int slotIndex);
CK_ULONG getParameterSetValue(const std::string& paramSet);
bool openSession(int slotIndex);
bool generateMLDSAKeypair(CK_ULONG paramSetValue, const std::string& keyLabel, int slotIndex, bool extractPublicKey);
bool extractPublicKeyToFile(CK_OBJECT_HANDLE hPublicKey, const std::string& keyLabel, const std::string& paramSet);

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
    std::cout << "=================================================================" << std::endl;
    std::cout << "PKCS#11 ML-DSA Key Generator (64-bit)" << std::endl;
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
    std::cout << "=========================" << std::endl;
    std::cout << "ML-DSA Key Pair Generator" << std::endl;
    std::cout << "=========================" << std::endl;
    std::cout << "Usage: " << programName << " [OPTIONS]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help                 Show this help message" << std::endl;
    std::cout << "  -l, --label LABEL          Set key label (default: MLDSA-KeyPair)" << std::endl;
    std::cout << "  -p, --params PARAM_SET     ML-DSA parameter set(s) to generate" << std::endl;
    std::cout << "                             Can be specified multiple times" << std::endl;
    std::cout << "                             Valid values: 44, 65, 87, all" << std::endl;
    std::cout << "  -s, --slot SLOT_INDEX      PKCS#11 slot index to use (default: 0)" << std::endl;
    std::cout << "                             Valid range: 0-20" << std::endl;
    std::cout << "  -e, --extract              Extract public key to file for sharing" << std::endl;
    std::cout << "                             File format: keyname_public.pem" << std::endl;
    std::cout << std::endl;
    std::cout << "Parameter Sets:" << std::endl;
    std::cout << "  44                         ML-DSA-44 (NIST Level 2, AES-128 equivalent)" << std::endl;
    std::cout << "  65                         ML-DSA-65 (NIST Level 3, AES-192 equivalent)" << std::endl;
    std::cout << "  87                         ML-DSA-87 (NIST Level 5, AES-256 equivalent)" << std::endl;
    std::cout << "  all                        Generate all parameter sets" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " -p 44 -l MyKey" << std::endl;
    std::cout << "  " << programName << " --params 65 --params 87 --slot 1" << std::endl;
    std::cout << "  " << programName << " -p all -s 2" << std::endl;
    std::cout << "  " << programName << " -p 44 -l TestKey --extract" << std::endl;
    std::cout << "  " << programName << " --help" << std::endl;
    std::cout << std::endl;
    std::cout << "If no parameter set is specified, all sets will be generated." << std::endl;
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
        else if (arg == "-p" || arg == "--params") {
            if (i + 1 < argc) {
                std::string paramSet = argv[++i];
                if (paramSet == "all") {
                    options.parameterSets = {"44", "65", "87"};
                } else if (isValidParameterSet(paramSet)) {
                    options.parameterSets.push_back(paramSet);
                } else {
                    std::cerr << "Error: Invalid parameter set '" << paramSet << "'" << std::endl;
                    std::cerr << "Valid values are: 44, 65, 87, all" << std::endl;
                    options.showHelp = true;
                    return options;
                }
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
                        std::cerr << "Valid range is: 0-20" << std::endl;
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
        else if (arg == "-e" || arg == "--extract") {
            options.extractPublicKey = true;
        }
        else {
            std::cerr << "Error: Unknown option '" << arg << "'" << std::endl;
            options.showHelp = true;
            return options;
        }
    }
    
    // If no parameter sets specified, use all
    if (options.parameterSets.empty()) {
        options.parameterSets = {"44", "65", "87"};
    }
    
    return options;
}

bool isValidParameterSet(const std::string& paramSet) {
    return paramSet == "44" || paramSet == "65" || paramSet == "87";
}

bool isValidSlotIndex(int slotIndex) {
    return slotIndex >= 0 && slotIndex <= 20;
}

CK_ULONG getParameterSetValue(const std::string& paramSet) {
    if (paramSet == "44") return CKP_ML_DSA_44;
    if (paramSet == "65") return CKP_ML_DSA_65;
    if (paramSet == "87") return CKP_ML_DSA_87;
    return 0; // Invalid
}

// Base64 encoding function
std::string base64Encode(const std::vector<CK_BYTE>& data) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, valb = -6;
    for (CK_BYTE c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (result.size() % 4) result.push_back('=');
    return result;
}

// Create ASN.1 DER structure for ML-DSA public key
std::vector<CK_BYTE> createMLDSAPublicKeyDER(const std::vector<CK_BYTE>& rawKey, const std::string& paramSet) {
    std::vector<CK_BYTE> der;
    
    // ASN.1 DER structure for ML-DSA public key:
    // SEQUENCE {
    //   SEQUENCE {
    //     OBJECT IDENTIFIER { 2.16.840.1.101.3.4.3.17 }  -- ML-DSA-44
    //     or 2.16.840.1.101.3.4.3.18 for ML-DSA-65
    //     or 2.16.840.1.101.3.4.3.19 for ML-DSA-87
    //   }
    //   BIT STRING { public key data }
    // }
    
    // ML-DSA OID based on parameter set
    std::vector<CK_BYTE> oid;
    if (paramSet == "44") {
        // 2.16.840.1.101.3.4.3.17 = 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11
        oid = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11};
    } else if (paramSet == "65") {
        // 2.16.840.1.101.3.4.3.18 = 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
        oid = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
    } else if (paramSet == "87") {
        // 2.16.840.1.101.3.4.3.19 = 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13
        oid = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13};
    }
    
    // Build the DER structure
    std::vector<CK_BYTE> algorithmId;
    algorithmId.push_back(0x30); // SEQUENCE
    algorithmId.push_back(static_cast<CK_BYTE>(2 + oid.size())); // Length
    algorithmId.push_back(0x06); // OBJECT IDENTIFIER
    algorithmId.push_back(static_cast<CK_BYTE>(oid.size())); // OID length
    algorithmId.insert(algorithmId.end(), oid.begin(), oid.end());
    
    // Public key bit string
    std::vector<CK_BYTE> publicKeyBits;
    publicKeyBits.push_back(0x03); // BIT STRING
    // Length calculation for bit string (1 byte for unused bits + key data)
    size_t bitStringLen = 1 + rawKey.size();
    if (bitStringLen < 128) {
        publicKeyBits.push_back(static_cast<CK_BYTE>(bitStringLen));
    } else if (bitStringLen < 256) {
        publicKeyBits.push_back(0x81);
        publicKeyBits.push_back(static_cast<CK_BYTE>(bitStringLen));
    } else {
        publicKeyBits.push_back(0x82);
        publicKeyBits.push_back(static_cast<CK_BYTE>(bitStringLen >> 8));
        publicKeyBits.push_back(static_cast<CK_BYTE>(bitStringLen & 0xFF));
    }
    publicKeyBits.push_back(0x00); // No unused bits
    publicKeyBits.insert(publicKeyBits.end(), rawKey.begin(), rawKey.end());
    
    // Main SEQUENCE
    der.push_back(0x30); // SEQUENCE
    size_t contentLen = algorithmId.size() + publicKeyBits.size();
    if (contentLen < 128) {
        der.push_back(static_cast<CK_BYTE>(contentLen));
    } else if (contentLen < 256) {
        der.push_back(0x81);
        der.push_back(static_cast<CK_BYTE>(contentLen));
    } else {
        der.push_back(0x82);
        der.push_back(static_cast<CK_BYTE>(contentLen >> 8));
        der.push_back(static_cast<CK_BYTE>(contentLen & 0xFF));
    }
    
    // Add algorithm identifier and public key
    der.insert(der.end(), algorithmId.begin(), algorithmId.end());
    der.insert(der.end(), publicKeyBits.begin(), publicKeyBits.end());
    
    return der;
}

bool extractPublicKeyToFile(CK_OBJECT_HANDLE hPublicKey, const std::string& keyLabel, const std::string& paramSet) {
    CK_RV rv;
    
    // Get the public key value
    CK_ATTRIBUTE pubKeyAttrs[] = {
        {CKA_VALUE, NULL_PTR, 0}
    };

    rv = pFunctionList->C_GetAttributeValue(hSession, hPublicKey, pubKeyAttrs, 1);
    if (rv != CKR_OK) {
        std::cerr << "Failed to get public key size: 0x" << std::hex << rv << std::endl;
        return false;
    }

    std::vector<CK_BYTE> publicKeyValue(pubKeyAttrs[0].ulValueLen);
    pubKeyAttrs[0].pValue = publicKeyValue.data();
    
    rv = pFunctionList->C_GetAttributeValue(hSession, hPublicKey, pubKeyAttrs, 1);
    if (rv != CKR_OK) {
        std::cerr << "Failed to get public key value: 0x" << std::hex << rv << std::endl;
        return false;
    }

    // Create filename with .pem extension for OpenSSL compatibility
    std::string filename = keyLabel + "public.pem";
    
    // Create ASN.1 DER structure
    std::vector<CK_BYTE> derData = createMLDSAPublicKeyDER(publicKeyValue, paramSet);
    
    // Base64 encode the DER data
    std::string base64Data = base64Encode(derData);
    
    // Write to file in PEM format
    std::ofstream outFile(filename);
    if (!outFile) {
        std::cerr << "Failed to create file: " << filename << std::endl;
        return false;
    }

    outFile << "-----BEGIN PUBLIC KEY-----" << std::endl;
    
    // Write base64 data in 64-character lines
    for (size_t i = 0; i < base64Data.length(); i += 64) {
        size_t len = std::min(size_t(64), base64Data.length() - i);
        outFile << base64Data.substr(i, len) << std::endl;
    }
    
    outFile << "-----END PUBLIC KEY-----" << std::endl;
    outFile.close();

    std::cout << "  Public key extracted to: " << filename << " (OpenSSL PEM format)" << std::endl;
    std::cout << "  DER size: " << derData.size() << " bytes, Raw key: " << publicKeyValue.size() << " bytes" << std::endl;
    
    return true;
}


bool generateMLDSAKeypair(CK_ULONG paramSetValue, const std::string& keyLabel, int slotIndex, bool extractPublicKey) {
    // Find parameter set info
    MLDSAParameterSet paramSet;
    bool found = false;
    for (const auto& ps : getMLDSAParameterSets()) {
        if (ps.parameterSet == paramSetValue) {
            paramSet = ps;
            found = true;
            break;
        }
    }
    if (!found) {
        std::cerr << "Unknown ML-DSA parameter set: " << paramSetValue << std::endl;
        return false;
    }

    std::cout << "\n" << std::string(80, '=') << std::endl;
    std::cout << "Generating " << paramSet.name << " key pair with label: " << keyLabel << std::endl;
    std::cout << "Description: " << paramSet.description << std::endl;
    std::cout << "NIST Security Level: " << paramSet.nistLevel << " (equivalent to " << paramSet.securityEquivalent << ")" << std::endl;
    std::cout << "Slot Index: " << slotIndex << std::endl;
    std::cout << std::string(80, '=') << std::endl;

    CK_RV rv;
    CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;

    // Start timing
    auto startTime = std::chrono::high_resolution_clock::now();

    // === Key Generation ===
    std::cout << "\n=== Key Pair Generation ===" << std::endl;

    CK_ULONG keyType = CKK_ML_DSA;
    CK_ML_DSA_PARAMETER_SET_TYPE parameterSetValue = static_cast<CK_ML_DSA_PARAMETER_SET_TYPE>(paramSet.parameterSet);
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;

    std::string pubLabel = keyLabel ;
    std::string privLabel = keyLabel ;

    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_VERIFY, &ckTrue, sizeof(ckTrue)},
        {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
        {CKA_LABEL, (CK_VOID_PTR)pubLabel.c_str(), static_cast<CK_ULONG>(pubLabel.size())},
        {CKA_PARAMETER_SET, ¶meterSetValue, sizeof(parameterSetValue)}
    };

    // For slot 0 (accelerator slot), use standard attributes
    // For slot 1+ (card/softcard slots), adjust attributes to avoid template errors
    CK_BBOOL sensitive = (slotIndex == 0) ? ckTrue : ckFalse;
    CK_BBOOL extractable = (slotIndex == 0) ? ckFalse : ckTrue;
    

    // For card slots, we need to adjust the private key attributes
    // to avoid the "sensitive/non-extractable objects on card slot must be private" error
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_CLASS, &privKeyClass, sizeof(privKeyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_SIGN, &ckTrue, sizeof(ckTrue)},
        {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
        {CKA_LABEL, (CK_VOID_PTR)privLabel.c_str(), static_cast<CK_ULONG>(privLabel.size())},
        {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
        {CKA_SENSITIVE, &sensitive, sizeof(sensitive)},
        {CKA_EXTRACTABLE, &extractable, sizeof(extractable)},
        {CKA_PARAMETER_SET, ¶meterSetValue, sizeof(parameterSetValue)}
    };

    CK_MECHANISM mechanism = {CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0};

    auto keyGenStart = std::chrono::high_resolution_clock::now();
    rv = pFunctionList->C_GenerateKeyPair(
        hSession,
        &mechanism,
        publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(publicKeyTemplate[0]),
        privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(privateKeyTemplate[0]),
        &hPublicKey,
        &hPrivateKey
    );
    auto keyGenEnd = std::chrono::high_resolution_clock::now();

    if (rv != CKR_OK) {
        std::cerr << "Key generation failed: 0x" << std::hex << rv << std::endl;
        std::cerr << "Note: " << paramSet.name << " may not be supported by this implementation" << std::endl;
        return false;
    }

    auto keyGenTime = std::chrono::duration_cast<std::chrono::milliseconds>(keyGenEnd - keyGenStart);
    std::cout << "SUCCESS: " << paramSet.name << " key pair generated successfully!" << std::endl;
    std::cout << "  Key generation time: " << keyGenTime.count() << " ms" << std::endl;

    // === Get Public Key Information ===
    CK_ATTRIBUTE pubKeyAttrs[] = {
        {CKA_VALUE, NULL_PTR, 0}
    };

    rv = pFunctionList->C_GetAttributeValue(hSession, hPublicKey, pubKeyAttrs, 1);
    if (rv == CKR_OK) {
        std::vector<CK_BYTE> publicKeyValue(pubKeyAttrs[0].ulValueLen);
        pubKeyAttrs[0].pValue = publicKeyValue.data();
        rv = pFunctionList->C_GetAttributeValue(hSession, hPublicKey, pubKeyAttrs, 1);

        if (rv == CKR_OK) {
            std::cout << "  Public key size: " << publicKeyValue.size() << " bytes";
            if (publicKeyValue.size() == static_cast<size_t>(paramSet.expectedPublicKeySize)) {
                std::cout << " (matches expected)" << std::endl;
            } else {
                std::cout << " (expected " << paramSet.expectedPublicKeySize << " bytes)" << std::endl;
            }
            
            // Extract public key to file if requested
            if (extractPublicKey) {
                std::string paramSetStr;
                if (paramSet.parameterSet == CKP_ML_DSA_44) paramSetStr = "44";
                else if (paramSet.parameterSet == CKP_ML_DSA_65) paramSetStr = "65";
                else if (paramSet.parameterSet == CKP_ML_DSA_87) paramSetStr = "87";
                
                if (!extractPublicKeyToFile(hPublicKey, keyLabel, paramSetStr)) {
                    std::cerr << "  Warning: Failed to extract public key to file" << std::endl;
                }
            }
        }
    }
    return true;
}

int main(int argc, char* argv[]) {
    // Parse command line arguments
    CommandLineOptions options = parseCommandLine(argc, argv);
    
    if (options.showHelp) {
        printHelp(argv[0]);
        return 0;
    }

    if (!initializePKCS11()) {
        return 1;
    }

    if (!openSession(options.slotIndex)) {
        cleanup();
        return 1;
    }

    // Generate ML-DSA key pairs for specified parameter sets
    bool allSuccessful = true;
    for (const std::string& paramSetStr : options.parameterSets) {
        CK_ULONG paramSetValue = getParameterSetValue(paramSetStr);
        if (paramSetValue == 0) {
            std::cerr << "Invalid parameter set: " << paramSetStr << std::endl;
            allSuccessful = false;
            continue;
        }
        
        // Use exact label for single parameter set, append parameter set for multiple
        std::string keyLabel = options.keyLabel;
        if (options.parameterSets.size() > 1) {
            keyLabel += "-" + paramSetStr;
        }
        
        if (!generateMLDSAKeypair(paramSetValue, keyLabel, options.slotIndex, options.extractPublicKey)) {
            allSuccessful = false;
            // Continue with other parameter sets even if one fails
        }
    }

    // Cleanup
    cleanup();
    std::cout << "\nPKCS#11 session closed and library finalized" << std::endl;
    
    if (allSuccessful) {
        std::cout << "All key pairs generated successfully!" << std::endl;
        return 0;
    } else {
        std::cout << "Failed to generate. Check the output above for details." << std::endl;
        return 1;
    }
}
