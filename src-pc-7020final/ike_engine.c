




#include "ike_protocol.h"
#include "crypto_hw.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"






static const uint8_t dh14_p[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};


static const uint8_t dh14_g[256] = {
    [0 ... 254] = 0x00,
    [255] = 0x02
};


static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context drbg_ctx;
static int rng_initialized = 0;




static void init_rng(void) {
    if (rng_initialized) return;
    mbedtls_entropy_init(&entropy_ctx);
    mbedtls_ctr_drbg_init(&drbg_ctx);
    mbedtls_ctr_drbg_seed(&drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
    rng_initialized = 1;
}

static void get_random_bytes(uint8_t *buf, int len) {
    if (!rng_initialized) {
        init_rng();
    }
    mbedtls_ctr_drbg_random(&drbg_ctx, buf, len);
}





static void build_header(ike_header_t *hdr, uint8_t msg_type, 
                         const uint8_t cky_i[8], const uint8_t cky_r[8], 
                         uint16_t payload_len) {
    hdr->msg_type = msg_type;
    hdr->reserved = 0;
    hdr->payload_len = ((payload_len & 0xFF) << 8) | ((payload_len >> 8) & 0xFF);
    memcpy(hdr->cky_i, cky_i, 8);
    memcpy(hdr->cky_r, cky_r, 8);
}

static uint16_t get_payload_len(const ike_header_t *hdr) {
    return (hdr->payload_len >> 8) | ((hdr->payload_len & 0xFF) << 8);
}





void ike_init(ike_context_t *ctx, ike_role_t role,
              const uint8_t *psk, uint8_t psk_len,
              uint32_t local_ip, uint32_t peer_ip) {
    memset(ctx, 0, sizeof(ike_context_t));
    ctx->role = role;
    memcpy(ctx->psk, psk, psk_len);
    ctx->psk_len = psk_len;
    ctx->local_ip = local_ip;
    ctx->peer_ip = peer_ip;
    init_rng();
    if (role == IKE_ROLE_INITIATOR) {
        get_random_bytes(ctx->cky_i, 8);
        get_random_bytes(ctx->nonce_i, NONCE_LEN);
    } else {
        get_random_bytes(ctx->cky_r, 8);
        get_random_bytes(ctx->nonce_r, NONCE_LEN);
    }
    /* 生成 DH 私钥（随机 256 字节），用于计算公钥 g^x mod p */
    get_random_bytes(ctx->dh_private, DH_KEY_LEN);
    dh_mod_exp(dh14_g, ctx->dh_private, dh14_p, ctx->dh_public);
    ctx->state = IKE_STATE_IDLE;
}

int ike_initiate(ike_context_t *ctx) {
    if (ctx->role != IKE_ROLE_INITIATOR) return -1;
    ctx->state = IKE_STATE_SA_INIT;
    return 0;
}

void ike_derive_keys(ike_context_t *ctx) {
    uint8_t msg_buf[512];
    memcpy(msg_buf, ctx->nonce_i, NONCE_LEN);
    memcpy(msg_buf + NONCE_LEN, ctx->nonce_r, NONCE_LEN);
    hw_hmac_sha1(ctx->psk, ctx->psk_len, msg_buf, NONCE_LEN * 2, ctx->skeyid);
    int offset = 0;
    memcpy(msg_buf + offset, ctx->dh_shared, DH_KEY_LEN); offset += DH_KEY_LEN;
    memcpy(msg_buf + offset, ctx->cky_i, 8); offset += 8;
    memcpy(msg_buf + offset, ctx->cky_r, 8); offset += 8;
    msg_buf[offset++] = 0;
    hw_hmac_sha1(ctx->skeyid, HASH_LEN, msg_buf, offset, ctx->skeyid_d);
    offset = 0;
    memcpy(msg_buf + offset, ctx->skeyid_d, HASH_LEN); offset += HASH_LEN;
    memcpy(msg_buf + offset, ctx->dh_shared, DH_KEY_LEN); offset += DH_KEY_LEN;
    memcpy(msg_buf + offset, ctx->cky_i, 8); offset += 8;
    memcpy(msg_buf + offset, ctx->cky_r, 8); offset += 8;
    msg_buf[offset++] = 1;
    hw_hmac_sha1(ctx->skeyid, HASH_LEN, msg_buf, offset, ctx->skeyid_a);
    offset = 0;
    memcpy(msg_buf + offset, ctx->skeyid_a, HASH_LEN); offset += HASH_LEN;
    memcpy(msg_buf + offset, ctx->dh_shared, DH_KEY_LEN); offset += DH_KEY_LEN;
    memcpy(msg_buf + offset, ctx->cky_i, 8); offset += 8;
    memcpy(msg_buf + offset, ctx->cky_r, 8); offset += 8;
    msg_buf[offset++] = 2;
    hw_hmac_sha1(ctx->skeyid, HASH_LEN, msg_buf, offset, ctx->skeyid_e);
    memcpy(ctx->sa.enc_key, ctx->skeyid_e, AES_KEY_LEN);
    memcpy(ctx->sa.auth_key, ctx->skeyid_a, HMAC_KEY_LEN);
    memset(ctx->sa.iv, 0, AES_KEY_LEN); 
    ctx->sa.peer_ip = ctx->peer_ip;
}

int ike_process_message(ike_context_t *ctx,
                        const uint8_t *data, uint16_t data_len,
                        uint8_t *resp, uint16_t *resp_len) {
    if (data_len < sizeof(ike_header_t)) return -1;
    const ike_header_t *hdr = (const ike_header_t *)data;
    const uint8_t *payload = data + sizeof(ike_header_t);
    uint16_t p_len = get_payload_len(hdr);
    *resp_len = 0;
    ike_header_t *resp_hdr = (ike_header_t *)resp;
    uint8_t *resp_payload = resp + sizeof(ike_header_t);
    switch (hdr->msg_type) {
        case IKE_MSG_SA_PROPOSE: {
            if (ctx->role == IKE_ROLE_RESPONDER) {
                memcpy(ctx->cky_i, hdr->cky_i, 8);
                memcpy(resp_payload, payload, p_len);
                build_header(resp_hdr, IKE_MSG_SA_ACCEPT, ctx->cky_i, ctx->cky_r, p_len);
                *resp_len = sizeof(ike_header_t) + p_len;
                ctx->state = IKE_STATE_SA_AGREED;
            }
            break;
        }
        case IKE_MSG_SA_ACCEPT: {
            if (ctx->role == IKE_ROLE_INITIATOR && ctx->state == IKE_STATE_SA_INIT) {
                memcpy(ctx->cky_r, hdr->cky_r, 8);
                memcpy(resp_payload, ctx->dh_public, DH_KEY_LEN);
                memcpy(resp_payload + DH_KEY_LEN, ctx->nonce_i, NONCE_LEN);
                build_header(resp_hdr, IKE_MSG_KE_NONCE, ctx->cky_i, ctx->cky_r, DH_KEY_LEN + NONCE_LEN);
                *resp_len = sizeof(ike_header_t) + DH_KEY_LEN + NONCE_LEN;
                ctx->state = IKE_STATE_KE_SENT;
            }
            break;
        }
        case IKE_MSG_KE_NONCE: {
            if (p_len < DH_KEY_LEN + NONCE_LEN) return -1;
            memcpy(ctx->dh_peer_pub, payload, DH_KEY_LEN);
            if (ctx->role == IKE_ROLE_INITIATOR) {
                memcpy(ctx->nonce_r, payload + DH_KEY_LEN, NONCE_LEN);
            } else {
                memcpy(ctx->nonce_i, payload + DH_KEY_LEN, NONCE_LEN);
            }
            dh_mod_exp(ctx->dh_peer_pub, ctx->dh_private, dh14_p, ctx->dh_shared);
            ike_derive_keys(ctx);
            if (ctx->role == IKE_ROLE_RESPONDER) {
                memcpy(resp_payload, ctx->dh_public, DH_KEY_LEN);
                memcpy(resp_payload + DH_KEY_LEN, ctx->nonce_r, NONCE_LEN);
                build_header(resp_hdr, IKE_MSG_KE_NONCE, ctx->cky_i, ctx->cky_r, DH_KEY_LEN + NONCE_LEN);
                *resp_len = sizeof(ike_header_t) + DH_KEY_LEN + NONCE_LEN;
            } else {
                uint8_t auth_data[32] = "INITIATOR_AUTH";
                uint16_t enc_len;
                ike_encrypt_data(ctx, auth_data, 16, resp_payload, &enc_len); 
                build_header(resp_hdr, IKE_MSG_AUTH, ctx->cky_i, ctx->cky_r, enc_len);
                *resp_len = sizeof(ike_header_t) + enc_len;
                ctx->state = IKE_STATE_AUTH_SENT;
            }
            break;
        }
        case IKE_MSG_AUTH: {
            uint8_t dec_data[64];
            uint16_t dec_len;
            if (ike_decrypt_data(ctx, payload, p_len, dec_data, &dec_len) == 0) {
                if (ctx->role == IKE_ROLE_RESPONDER) {
                    uint8_t auth_data[32] = "RESPONDER_AUTH";
                    uint16_t enc_len;
                    ike_encrypt_data(ctx, auth_data, 16, resp_payload, &enc_len);
                    build_header(resp_hdr, IKE_MSG_AUTH, ctx->cky_i, ctx->cky_r, enc_len);
                    *resp_len = sizeof(ike_header_t) + enc_len;
                }
                ctx->state = IKE_STATE_ESTABLISHED;
                ctx->sa.state = IKE_STATE_ESTABLISHED;
            } else {
                return -1;
            }
            break;
        }
        case IKE_MSG_DATA: {
            if (ctx->state != IKE_STATE_ESTABLISHED) return -1;
            uint8_t dec_data[1024];
            uint16_t dec_len;
            if (ike_decrypt_data(ctx, payload, p_len, dec_data, &dec_len) == 0) {
                if (dec_len < 1024) dec_data[dec_len] = '\0';
                printf("\n[IKE] Decrypted Data: %s\n\n", (char*)dec_data);

                uint16_t enc_len;
                ike_encrypt_data(ctx, dec_data, dec_len, resp_payload, &enc_len);
                build_header(resp_hdr, IKE_MSG_DATA, ctx->cky_i, ctx->cky_r, enc_len);
                *resp_len = sizeof(ike_header_t) + enc_len;
            } else {
                printf("[IKE] DATA decryption or verification failed!\n");
                return -1;
            }
            break;
        }
        default:
            return -1;
    }
    return 0;
}

int ike_encrypt_data(ike_context_t *ctx,
                     const uint8_t *plaintext, uint16_t plain_len,
                     uint8_t *ciphertext, uint16_t *cipher_len) {
    uint8_t enc_buf[1024 + 16]; 
    uint16_t padded_len;
    uint8_t pad_val;
    pad_val = 16 - (plain_len % 16);
    padded_len = plain_len + pad_val;
    if (padded_len > sizeof(enc_buf)) return -1;
    memcpy(enc_buf, plaintext, plain_len);
    for (int i = 0; i < pad_val; i++) {
        enc_buf[plain_len + i] = pad_val;
    }
    uint8_t iv[AES_KEY_LEN];
    get_random_bytes(iv, AES_KEY_LEN);
    hw_aes128_cbc_encrypt(ctx->sa.enc_key, iv, enc_buf, padded_len, enc_buf);
    memcpy(ciphertext, iv, AES_KEY_LEN);
    memcpy(ciphertext + AES_KEY_LEN, enc_buf, padded_len);
    uint8_t hmac[HMAC_KEY_LEN];
    hw_hmac_sha1(ctx->sa.auth_key, HMAC_KEY_LEN, ciphertext, AES_KEY_LEN + padded_len, hmac);
    memcpy(ciphertext + AES_KEY_LEN + padded_len, hmac, HMAC_KEY_LEN);
    *cipher_len = AES_KEY_LEN + padded_len + HMAC_KEY_LEN;
    return 0;
}

int ike_decrypt_data(ike_context_t *ctx,
                     const uint8_t *ciphertext, uint16_t cipher_len,
                     uint8_t *plaintext, uint16_t *plain_len) {
    if (cipher_len < AES_KEY_LEN + HMAC_KEY_LEN) return -1;
    uint16_t enc_len = cipher_len - AES_KEY_LEN - HMAC_KEY_LEN;
    if (enc_len % AES_KEY_LEN != 0) return -1;
    const uint8_t *iv = ciphertext;
    const uint8_t *enc_data = ciphertext + AES_KEY_LEN;
    const uint8_t *received_hmac = ciphertext + AES_KEY_LEN + enc_len;
    uint8_t computed_hmac[HMAC_KEY_LEN];
    hw_hmac_sha1(ctx->sa.auth_key, HMAC_KEY_LEN, ciphertext, AES_KEY_LEN + enc_len, computed_hmac);
    if (memcmp(received_hmac, computed_hmac, HMAC_KEY_LEN) != 0) {
        return -1;
    }
    hw_aes128_cbc_decrypt(ctx->sa.enc_key, iv, enc_data, enc_len, plaintext);
    if (enc_len > 0) {
        uint8_t pad_len = plaintext[enc_len - 1];
        if (pad_len > 0 && pad_len <= AES_KEY_LEN) {
            int i;
            int valid = 1;
            for (i = 0; i < pad_len; i++) {
                if (plaintext[enc_len - 1 - i] != pad_len) {
                    valid = 0;
                    break;
                }
            }
            if (valid) {
                *plain_len = enc_len - pad_len;
            } else {
                *plain_len = enc_len; 
            }
        } else {
            *plain_len = enc_len; 
        }
    } else {
        *plain_len = 0;
    }
    return 0;
}
