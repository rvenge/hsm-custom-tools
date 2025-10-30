// Directives
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI40; 

// Define the PKCS#11 library path and load it
const string libraryPath = @"C:\Program Files\nCipher\nfast\toolkits\pkcs11\cknfast.dll"; // change to /opt/nfast/toolkits/pkcs11/libcknfast.co if Linux

// Load the PKCS#11 library
var factories = new Pkcs11InteropFactories();
var library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, libraryPath, AppType.MultiThreaded);

// Get the list of slots with a token present
var slots = library.GetSlotList(SlotsType.WithTokenPresent);

// Use slot 0 for the operation
var session = slots[0].OpenSession(SessionType.ReadWrite); // Open a read-write session using Slot 0

// Define the curve ID and private key value EC parameters
var curveId = new byte[] { 6, 8, 42, 134, 72, 206, 61, 3, 1, 7 }; // Example curve ID for secp256r1

// Example private key value (d) for the EC key pair. 32 bytes for secp256r1
//var d = new byte[]
//{
//    81, 155, 66, 61, 113, 95, 139, 88, 31, 79, 168, 238, 89, 244, 119, 26,
//    91, 68, 200, 19, 11, 78, 62, 172, 202, 84, 165, 109, 218, 114, 180, 100
//};

// The value (d) can be static as shown above or randomly generated.

// Generate a random private key value (d) for the EC key pair
byte[] d = new byte[32]; // 32 bytes for secp256r1
RandomNumberGenerator.Fill(d); // Use the static method to fill the array with random bytes

Console.WriteLine(" ");
Console.WriteLine("Private key value (d): " + BitConverter.ToString(d).Replace("-", ""));
 
// Create a list of object attributes for the private key
var oaFactory = session.Factories.ObjectAttributeFactory;
var attributes = new List<IObjectAttribute>
{
    oaFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
    oaFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
    oaFactory.Create(CKA.CKA_EC_PARAMS, curveId),
    oaFactory.Create(CKA.CKA_VALUE, d),
    oaFactory.Create(CKA.CKA_SENSITIVE, true),
    oaFactory.Create(CKA.CKA_LABEL, "TestKey"),
    oaFactory.Create(CKA.CKA_SIGN, true),    
    oaFactory.Create(CKA.CKA_DERIVE, true), 
    oaFactory.Create(CKA.CKA_EXTRACTABLE, false), // If you wish to extract the key set to true
    oaFactory.Create(CKA.CKA_WRAP_WITH_TRUSTED, true), // If you wish to wrap the key set to true. Key wrapping should only be done with CKA_TRUSTED true keys
    oaFactory.Create(CKA.CKA_TOKEN, true), // Set to true if the key should be stored on the token
};

// Attempt to create the key
try
{
    var key = session.CreateObject(attributes);
    
    // Retrieve attributes of the created key
    var labelAttribute = session.GetAttributeValue(key, new List<CKA> { CKA.CKA_LABEL, CKA.CKA_CLASS, CKA.CKA_KEY_TYPE, CKA.CKA_EC_PARAMS, CKA.CKA_SENSITIVE, 
    CKA.CKA_SIGN, CKA.CKA_DERIVE, CKA.CKA_EXTRACTABLE, CKA.CKA_WRAP_WITH_TRUSTED });
   
// Fetch the values
string label = labelAttribute[0].GetValueAsString();
ulong keyClass = labelAttribute[1].GetValueAsUlong();
ulong keyType = labelAttribute[2].GetValueAsUlong();
byte[] ecParams = labelAttribute[3].GetValueAsByteArray();
bool sensitive = labelAttribute[4].GetValueAsByteArray()[0] == 1;
bool sign = labelAttribute[5].GetValueAsByteArray()[0] == 1;
bool derive = labelAttribute[6].GetValueAsByteArray()[0] == 1;
bool extractable = labelAttribute[7].GetValueAsByteArray()[0] == 1;
bool wrapWithTrusted = labelAttribute[8].GetValueAsByteArray()[0] == 1;

// Print the attributes
Console.WriteLine(" "); 
Console.WriteLine("Private Key created successfully.");
Console.WriteLine(" "); 
Console.WriteLine("Key attributes:");
Console.WriteLine($"Key label: {label}");
Console.WriteLine($"Key class: {(CKO)keyClass}");
Console.WriteLine($"Key type: {(CKK)keyType}");
Console.WriteLine($"Curve ID: {BitConverter.ToString(ecParams)}");
Console.WriteLine($"Sensitive: {sensitive}");
Console.WriteLine($"Sign: {sign}");
Console.WriteLine($"Derive: {derive}");
Console.WriteLine($"Extractable: {extractable}");
Console.WriteLine($"Wrap with trusted: {wrapWithTrusted}");
    
}
catch (Pkcs11Exception ex)
{
    // Error logging
    Console.WriteLine($"Error creating key: {ex.Message}");
}
