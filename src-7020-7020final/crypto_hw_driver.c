







#include "crypto_hw.h"
#include <string.h>
#include "mbedtls/md.h"
#include "mbedtls/aes.h"









static void wait_status_bit(uint32_t base, uint32_t offset, uint32_t mask)
{
    while (!(HW_READ32(base, offset) & mask)) {
    }
}





static void write_bytes_to_regs(uint32_t base, uint32_t start_offset,
                                const uint8_t *data, uint32_t byte_count)
{
    uint32_t word_count = byte_count / 4;
    for (uint32_t i = 0; i < word_count; i++) {
        uint32_t val = ((uint32_t)data[i*4]   << 24) |
                       ((uint32_t)data[i*4+1] << 16) |
                       ((uint32_t)data[i*4+2] << 8)  |
                       ((uint32_t)data[i*4+3]);
        HW_WRITE32(base, start_offset + i * 4, val);
    }
}




static void read_bytes_from_regs(uint32_t base, uint32_t start_offset,
                                 uint8_t *data, uint32_t byte_count)
{
    uint32_t word_count = byte_count / 4;
    for (uint32_t i = 0; i < word_count; i++) {
        uint32_t val = HW_READ32(base, start_offset + i * 4);
        data[i*4]   = (val >> 24) & 0xFF;
        data[i*4+1] = (val >> 16) & 0xFF;
        data[i*4+2] = (val >> 8)  & 0xFF;
        data[i*4+3] = val & 0xFF;
    }
}





void aes_load_key(const uint8_t key[16])
{
    write_bytes_to_regs(AES_BASE_ADDR, AES_KEY0_OFFSET, key, 16);

    HW_WRITE32(AES_BASE_ADDR, AES_CTRL_OFFSET, AES_CTRL_KEY_LOAD);

    wait_status_bit(AES_BASE_ADDR, AES_STATUS_OFFSET, AES_STATUS_KEY_READY);
}

void aes_load_iv(const uint8_t iv[16])
{
    write_bytes_to_regs(AES_BASE_ADDR, AES_IV0_OFFSET, iv, 16);
    HW_WRITE32(AES_BASE_ADDR, AES_CTRL_OFFSET, AES_CTRL_IV_LOAD);
}

void aes_encrypt_block(const uint8_t plaintext[16], uint8_t ciphertext[16])
{
    write_bytes_to_regs(AES_BASE_ADDR, AES_DIN0_OFFSET, plaintext, 16);

    HW_WRITE32(AES_BASE_ADDR, AES_CTRL_OFFSET, AES_CTRL_START);

    wait_status_bit(AES_BASE_ADDR, AES_STATUS_OFFSET, AES_STATUS_DONE);

    read_bytes_from_regs(AES_BASE_ADDR, AES_DOUT0_OFFSET, ciphertext, 16);
}

void aes_decrypt_block(const uint8_t ciphertext[16], uint8_t plaintext[16])
{

    write_bytes_to_regs(AES_BASE_ADDR, AES_DIN0_OFFSET, ciphertext, 16);

    HW_WRITE32(AES_BASE_ADDR, AES_CTRL_OFFSET, 
               AES_CTRL_START | AES_CTRL_DECRYPT);


    wait_status_bit(AES_BASE_ADDR, AES_STATUS_OFFSET, AES_STATUS_DONE);

    read_bytes_from_regs(AES_BASE_ADDR, AES_DOUT0_OFFSET, plaintext, 16);
}





void hmac_sha1_compute(const uint8_t *key, uint8_t key_len,
                       const uint8_t *msg, uint8_t msg_len,
                       uint8_t hmac[20])
{
    uint8_t key_padded[64];
    uint8_t msg_padded[64];

    memset(key_padded, 0, 64);
    memcpy(key_padded, key, (key_len <= 64) ? key_len : 64);

    memset(msg_padded, 0, 64);
    memcpy(msg_padded, msg, (msg_len <= 64) ? msg_len : 64);

    write_bytes_to_regs(HMAC_BASE_ADDR, HMAC_KEY0_OFFSET, key_padded, 64);

    write_bytes_to_regs(HMAC_BASE_ADDR, HMAC_MSG0_OFFSET, msg_padded, 64);

    HW_WRITE32(HMAC_BASE_ADDR, HMAC_MSGLEN_OFFSET, (uint32_t)msg_len);

    HW_WRITE32(HMAC_BASE_ADDR, HMAC_CTRL_OFFSET, 1);

    wait_status_bit(HMAC_BASE_ADDR, HMAC_STATUS_OFFSET, 1);

    read_bytes_from_regs(HMAC_BASE_ADDR, HMAC_HASH0_OFFSET, hmac, 20);
}




#include "mbedtls/bignum.h"

void dh_mod_exp(const uint8_t base[256], const uint8_t exp[256],
                const uint8_t modulus[256], uint8_t result[256])
{
    mbedtls_mpi b_base, b_exp, b_mod, b_res;

    mbedtls_mpi_init(&b_base);
    mbedtls_mpi_init(&b_exp);
    mbedtls_mpi_init(&b_mod);
    mbedtls_mpi_init(&b_res);

    mbedtls_mpi_read_binary(&b_base, base, 256);
    mbedtls_mpi_read_binary(&b_exp, exp, 256);
    mbedtls_mpi_read_binary(&b_mod, modulus, 256);
    int ret = mbedtls_mpi_exp_mod(&b_res, &b_base, &b_exp, &b_mod, NULL);
    if (ret != 0) {
        printf("[IKE] ERROR: mbedtls_mpi_exp_mod failed! Return code: -0x%04x\n", -ret);
    }
    memset(result, 0, 256);
    mbedtls_mpi_write_binary(&b_res, result, 256);
    mbedtls_mpi_free(&b_base);
    mbedtls_mpi_free(&b_exp);
    mbedtls_mpi_free(&b_mod);
    mbedtls_mpi_free(&b_res);
}





void hw_aes128_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                           const uint8_t *plaintext, uint32_t len, uint8_t *ciphertext)
{
    aes_load_key(key);
    aes_load_iv(iv);
    for (uint32_t i = 0; i < len; i += 16) {
        aes_encrypt_block(plaintext + i, ciphertext + i);
    }
}

void hw_aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                           const uint8_t *ciphertext, uint32_t len, uint8_t *plaintext)
{
    aes_load_key(key);
    aes_load_iv(iv);
    for (uint32_t i = 0; i < len; i += 16) {
        aes_decrypt_block(ciphertext + i, plaintext + i);
    }
}

void hw_hmac_sha1(const uint8_t *key, uint8_t key_len,
                  const uint8_t *msg, uint32_t msg_len, uint8_t hmac[20])
{

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    mbedtls_md_hmac(md_info, key, key_len, msg, msg_len, hmac);
}
