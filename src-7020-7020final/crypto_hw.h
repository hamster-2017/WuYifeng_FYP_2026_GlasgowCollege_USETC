








#ifndef CRYPTO_HW_H
#define CRYPTO_HW_H

#include <stdint.h>




#define AES_BASE_ADDR   0x43C00000U
#define HMAC_BASE_ADDR  0x43C10000U
#define DH_BASE_ADDR    0x43C20000U




#define AES_CTRL_OFFSET     0x00
#define AES_STATUS_OFFSET   0x04
#define AES_KEY0_OFFSET     0x10
#define AES_IV0_OFFSET      0x20
#define AES_DIN0_OFFSET     0x30
#define AES_DOUT0_OFFSET    0x40


#define AES_CTRL_START      (1U << 0)
#define AES_CTRL_DECRYPT    (1U << 1)
#define AES_CTRL_KEY_LOAD   (1U << 2)
#define AES_CTRL_IV_LOAD    (1U << 3)


#define AES_STATUS_DONE       (1U << 0)
#define AES_STATUS_KEY_READY  (1U << 1)




#define HMAC_CTRL_OFFSET    0x00
#define HMAC_STATUS_OFFSET  0x04
#define HMAC_MSGLEN_OFFSET  0x08
#define HMAC_KEY0_OFFSET    0x10
#define HMAC_MSG0_OFFSET    0x50
#define HMAC_HASH0_OFFSET   0x90






#define HW_WRITE32(base, offset, val) \
    (*(volatile uint32_t *)((base) + (offset)) = (val))

#define HW_READ32(base, offset) \
    (*(volatile uint32_t *)((base) + (offset)))









void aes_load_key(const uint8_t key[16]);





void aes_load_iv(const uint8_t iv[16]);






void aes_encrypt_block(const uint8_t plaintext[16], uint8_t ciphertext[16]);






void aes_decrypt_block(const uint8_t ciphertext[16], uint8_t plaintext[16]);









void hmac_sha1_compute(const uint8_t *key, uint8_t key_len,
                       const uint8_t *msg, uint8_t msg_len,
                       uint8_t hmac[20]);



#endif 
