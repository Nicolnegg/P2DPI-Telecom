#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

/*
 * Generates a fixed EC point `h` on the P-256 curve by multiplying
 * the generator by a random scalar. Saves `h` as a hex string to
 * "h_fixed.txt" in the executable's directory.
*/

int main(int argc, char *argv[]) {
    int ret = 1;
    EC_GROUP *group = NULL;
    EC_POINT *h = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *rand_bn = NULL;
    BIGNUM *order = NULL;
    char *h_hex = NULL;
    FILE *f = NULL;

    // Get the directory of the executable
    char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len == -1) {
        perror("readlink failed");
        goto cleanup;
    }
    path[len] = '\0';
    char *dir = dirname(path);

    // Create the output file path (same dir as binary)
    char filepath[1060];
    snprintf(filepath, sizeof(filepath), "%s/h_fixed.txt", dir);

    // Create EC group
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) { fprintf(stderr, "Failed to create EC group\n"); goto cleanup; }

    ctx = BN_CTX_new();
    if (!ctx) { fprintf(stderr, "Failed to create BN_CTX\n"); goto cleanup; }

    h = EC_POINT_new(group);
    if (!h) { fprintf(stderr, "Failed to create EC_POINT\n"); goto cleanup; }

    rand_bn = BN_new();
    if (!rand_bn) { fprintf(stderr, "Failed to create BIGNUM\n"); goto cleanup; }

    order = BN_new();
    if (!order) { fprintf(stderr, "Failed to create BIGNUM for order\n"); goto cleanup; }

    if (!EC_GROUP_get_order(group, order, ctx)) {
        fprintf(stderr, "Failed to get EC group order\n"); goto cleanup;
    }

    if (!BN_rand_range(rand_bn, order)) {
        fprintf(stderr, "Failed to generate random scalar\n"); goto cleanup;
    }

    if (!EC_POINT_mul(group, h, rand_bn, NULL, NULL, ctx)) {
        fprintf(stderr, "Failed to compute EC_POINT * scalar\n"); goto cleanup;
    }

    h_hex = EC_POINT_point2hex(group, h, POINT_CONVERSION_UNCOMPRESSED, ctx);
    if (!h_hex) {
        fprintf(stderr, "Failed to convert EC_POINT to hex\n"); goto cleanup;
    }

    // Save to file in executable's directory
    f = fopen(filepath, "w");
    if (!f) {
        fprintf(stderr, "Failed to open file for writing: %s\n", filepath);
        goto cleanup;
    }
    fprintf(f, "%s\n", h_hex);
    fclose(f);
    f = NULL;

    printf("Generated fixed point h:\n%s\n", h_hex);
    printf("Saved to %s\n", filepath);

    ret = 0;

cleanup:
    if (f) fclose(f);
    if (h_hex) OPENSSL_free(h_hex);
    if (rand_bn) BN_free(rand_bn);
    if (order) BN_free(order);
    if (h) EC_POINT_free(h);
    if (ctx) BN_CTX_free(ctx);
    if (group) EC_GROUP_free(group);

    return ret;
}
