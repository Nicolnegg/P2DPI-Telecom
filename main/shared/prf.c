#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>        // For elliptic curve operations
#include <openssl/bn.h>        // For big numbers
#include <openssl/aes.h>       // For AES encryption
#include <openssl/evp.h>       // OpenSSL's high-level crypto API
#include <openssl/rand.h>      // For generating random numbers

const unsigned char SALT[16] = {
    0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef,
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xba, 0xdc, 0xfe
}; // Static salt for AES encryption in H1

// === H1(x) := AES128_x(SALT) ===
// Simulates a programmable random oracle using AES as PRF
int H1(unsigned char *key, unsigned char *output) {
    unsigned char input[16];
    memcpy(input, SALT, 16);  // Use the first 16 bytes of the salt

    // Initialize the AES key with the given key x
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        fprintf(stderr, "EVP_EncryptInit_ex failed.\n");
        return 0;
    }

    if (!EVP_EncryptUpdate(ctx, output, &len, input, 16)) {
        fprintf(stderr, "EVP_EncryptUpdate failed.\n");
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// === F_KH(k, x) := (g^H1(x) * h)^k ===
// Key-homomorphic PRF using elliptic curve exponentiation
int FKH(BIGNUM *k, unsigned char *x_key, EC_POINT *h_fixed, EC_GROUP *group, EC_POINT *result, BN_CTX *ctx) {
    unsigned char h1_output[16];

    // Compute H1(x) using AES
    if (!H1(x_key, h1_output)) return 0;

    // Convert AES output to BIGNUM for exponentiation
    BIGNUM *h1_bn = BN_bin2bn(h1_output, 16, NULL);
    if (!h1_bn) return 0;

    // Get the base point generator g of the curve
    const EC_POINT *g = EC_GROUP_get0_generator(group);

    // Compute g^H1(x)
    EC_POINT *g_h1 = EC_POINT_new(group);
    EC_POINT_mul(group, g_h1, NULL, g, h1_bn, ctx);

    // Compute g^H1(x) * h_fixed (h fijo de la sesión)
    EC_POINT *product = EC_POINT_new(group);
    EC_POINT_add(group, product, g_h1, h_fixed, ctx);

    

    // Raise the result to power k: (g^H1(x) * h)^k
    EC_POINT_mul(group, result, NULL, product, k, ctx);

    // Cleanup memory
    EC_POINT_free(g_h1);
    EC_POINT_free(product);
    BN_free(h1_bn);

    return 1;
}


// === FKH_hex ===
//  raw token bytes (copied into a 16-byte buffer)
// Exportable version of FKH for use in Python (via ctypes)
int FKH_hex(const char* key_str, const char* k_str, const char* h_fixed_hex, char* output_hex, int max_len) {
    // Create a new EC_GROUP object for the NIST P-256 curve
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    // Create a new BN_CTX object for temporary BIGNUM variables and computations
    BN_CTX *ctx = BN_CTX_new();

    // Prepare the 16-byte key buffer initialized with zeros
    unsigned char key[16] = {0};
    // Copy the input key string into the key buffer (ensure max 16 bytes)
    strncpy((char*)key, key_str, 16);

    // Convert the hex string k_str to a BIGNUM object 'k'
    BIGNUM *k = NULL;
    BN_hex2bn(&k, k_str);

    // Create a new EC_POINT object to hold the fixed 'h' point from the session
    EC_POINT *h_fixed = EC_POINT_new(group);
    // Convert the input hex string representation of h_fixed to EC_POINT structure
    EC_POINT_hex2point(group, h_fixed_hex, h_fixed, ctx);

    // Create an EC_POINT object to hold the final result of the computation
    EC_POINT *res = EC_POINT_new(group);

    // Call the core FKH function:
    // Computes (g^{H1(x)} * h_fixed)^k over the elliptic curve group
    int ret = FKH(k, key, h_fixed, group, res, ctx);

    // Convert the resulting EC_POINT 'res' to a hex string in uncompressed format
    char *pt_hex = EC_POINT_point2hex(group, res, POINT_CONVERSION_UNCOMPRESSED, ctx);
    // Copy the hex string result safely into the output buffer
    strncpy(output_hex, pt_hex, max_len - 1);
    // Ensure null termination
    output_hex[max_len - 1] = '\0';

    // Free the memory allocated for the hex string by OpenSSL
    OPENSSL_free(pt_hex);
    // Free allocated EC_POINT objects and BIGNUMs
    EC_POINT_free(res);
    EC_POINT_free(h_fixed);
    BN_free(k);
    // Free the BN_CTX context
    BN_CTX_free(ctx);
    // Free the EC_GROUP object
    EC_GROUP_free(group);

    // Return the result of the FKH call (1 on success, 0 on failure)
    return ret;
}

// Inverse function for P2DPI:
// Given a point I_hex (an EC point in hex string) and kmb_hex (key in hex string),
// computes S = I^{kmb^{-1} mod order} and returns the result in output_hex.

int FKH_inv_hex(const char* I_hex, const char* kmb_hex, char* output_hex, int max_len) {
    int ret = 0;
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *kmb = NULL;
    BIGNUM *order = NULL;
    BIGNUM *kmb_inv = NULL;
    EC_POINT *I_point = NULL;
    EC_POINT *S_point = NULL;

    // Check input pointers
    if (!I_hex || !kmb_hex || !output_hex) return 0;

    // Create a new BN context for temporary variables
    ctx = BN_CTX_new();
    if (!ctx) goto cleanup;

    // Create a new EC group object for the curve P-256
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) goto cleanup;

    // Allocate BIGNUM variables
    order = BN_new();
    kmb = BN_new();
    kmb_inv = BN_new();
    if (!order || !kmb || !kmb_inv) goto cleanup;

    // Get the order of the EC group (prime order p)
    if (!EC_GROUP_get_order(group, order, ctx)) goto cleanup;

    // Convert kmb_hex (hex string) to BIGNUM kmb
    if (!BN_hex2bn(&kmb, kmb_hex)) goto cleanup;

    // Compute modular inverse of kmb modulo order, i.e. kmb_inv = kmb^{-1} mod p
    if (!BN_mod_inverse(kmb_inv, kmb, order, ctx)) goto cleanup;

    // Create a new EC_POINT to hold input point I
    I_point = EC_POINT_new(group);
    if (!I_point) goto cleanup;

    // Convert I_hex (hex string) to EC_POINT structure
    if (!EC_POINT_hex2point(group, I_hex, I_point, ctx)) goto cleanup;

    // Create a new EC_POINT to hold the output S
    S_point = EC_POINT_new(group);
    if (!S_point) goto cleanup;

    // Compute S_point = I_point ^ kmb_inv (scalar multiplication)
    if (!EC_POINT_mul(group, S_point, NULL, I_point, kmb_inv, ctx)) goto cleanup;

    // Convert S_point to hex string representation (uncompressed format)
    char *hex_str = EC_POINT_point2hex(group, S_point, POINT_CONVERSION_UNCOMPRESSED, ctx);
    if (!hex_str) goto cleanup;

    // Copy the hex string result into the output buffer safely
    strncpy(output_hex, hex_str, max_len - 1);
    output_hex[max_len - 1] = '\0';

    // Free the memory allocated by OpenSSL for the hex string
    OPENSSL_free(hex_str);

    ret = 1; // Success

cleanup:
    if (I_point) EC_POINT_free(I_point);
    if (S_point) EC_POINT_free(S_point);
    if (kmb) BN_free(kmb);
    if (kmb_inv) BN_free(kmb_inv);
    if (order) BN_free(order);
    if (group) EC_GROUP_free(group);
    if (ctx) BN_CTX_free(ctx);

    return ret;
}

int EC_POINT_exp_hex(const char* Ri_hex, const char* kSR_hex, char* output_hex, int max_len) {
    // Create elliptic curve group and big number context
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *ctx = BN_CTX_new();
    if (!group || !ctx) return 0;

    // Convert Ri (hex string) to EC_POINT
    EC_POINT *point_Ri = EC_POINT_new(group);
    if (!EC_POINT_hex2point(group, Ri_hex, point_Ri, ctx)) {
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
        EC_POINT_free(point_Ri);
        return 0;
    }

    // Convert kSR (hex string) to BIGNUM
    BIGNUM *kSR = NULL;
    if (!BN_hex2bn(&kSR, kSR_hex)) {
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
        EC_POINT_free(point_Ri);
        return 0;
    }

    // Compute I_i = R_i ^ kSR (scalar multiplication)
    EC_POINT *point_Ii = EC_POINT_new(group);
    if (!EC_POINT_mul(group, point_Ii, NULL, point_Ri, kSR, ctx)) {
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
        EC_POINT_free(point_Ri);
        BN_free(kSR);
        EC_POINT_free(point_Ii);
        return 0;
    }

    // Convert resulting point I_i to hex string
    char *hex_res = EC_POINT_point2hex(group, point_Ii, POINT_CONVERSION_UNCOMPRESSED, ctx);
    if (!hex_res) {
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
        EC_POINT_free(point_Ri);
        BN_free(kSR);
        EC_POINT_free(point_Ii);
        return 0;
    }

    // Copy hex result to output buffer
    strncpy(output_hex, hex_res, max_len - 1);
    output_hex[max_len - 1] = '\0';  // Ensure null-termination

    // Free all allocated resources
    OPENSSL_free(hex_res);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    EC_POINT_free(point_Ri);
    BN_free(kSR);
    EC_POINT_free(point_Ii);

    return 1;
}

// H2 function: AES-128-ECB encryption with key 'h_key' on input 'y_bytes' (16 bytes)
int H2(const unsigned char *y_bytes, int y_len, const unsigned char *h_key, unsigned char *output) {
    // Check input length; y_bytes must be exactly 16 bytes for AES block size
    if (y_len != 16) {
        fprintf(stderr, "H2 input y must be 16 bytes\n");
        return 0;
    }

    // Create and initialize a new EVP cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0;

    // Initialize encryption operation with AES-128-ECB mode and the provided key
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, h_key, NULL)) {
        fprintf(stderr, "EVP_EncryptInit_ex failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Disable padding to ensure output is exactly 16 bytes (AES block size)
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Perform the encryption of the input data y_bytes
    if (!EVP_EncryptUpdate(ctx, output, &out_len, y_bytes, y_len)) {
        fprintf(stderr, "EVP_EncryptUpdate failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Clean up and free the cipher context
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}


