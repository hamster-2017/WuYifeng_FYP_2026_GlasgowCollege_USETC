#include <stdio.h>
#include "xil_printf.h"
#include "xil_cache.h"
#include "xparameters.h"

#include "ike_protocol.h"
#include "sa_manager.h"
#include "network.h"
#include "crypto_hw.h"
#include "platform.h"

//void run_verification() {
//    xil_printf("\r\n--- STARTING FUNCTIONAL VERIFICATION ---\r\n");
//   
//    uint8_t aes_key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
//    uint8_t aes_iv[16]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
//    uint8_t aes_plain[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
//    uint8_t aes_cipher[16];
//    uint8_t aes_expected[16] = {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d};
//
//    hw_aes128_cbc_encrypt(aes_key, aes_iv, aes_plain, 16, aes_cipher);
//    if(memcmp(aes_cipher, aes_expected, 16) == 0)
//        xil_printf("[PASS] T-AES-01: NIST Vector Match.\r\n");
//    else xil_printf("[FAIL] T-AES-01: NIST Vector Mismatch!\r\n");
//    
//    uint8_t hmac_key[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
//    uint8_t hmac_data[8] = "Hi There";
//    uint8_t hmac_actual[20];
//    uint8_t hmac_expected[20] = {0xb6,0x17,0x31,0x86,0x55,0x05,0x72,0x64,0xe2,0x8b,0xc0,0xb6,0xfb,0x37,0x8c,0x8e,0xf1,0x46,0xbe,0x00};
//
//    hmac_sha1_compute(hmac_key, 20, hmac_data, 8, hmac_actual);
//    if(memcmp(hmac_actual, hmac_expected, 20) == 0)
//        xil_printf("[PASS] T-HMAC-01: RFC 2104 Vector Match.\r\n");
//    else xil_printf("[FAIL] T-HMAC-01: HMAC Mismatch!\r\n");
//  
//    ike_context_t test_ctx;
//    memcpy(test_ctx.sa.enc_key, aes_key, 16);
//    memcpy(test_ctx.sa.auth_key, hmac_key, 20);
//    test_ctx.state = IKE_STATE_ESTABLISHED;
//    uint8_t msg[] = "This is a secret message!";
//    uint8_t packet[128];
//    uint16_t packet_len;
//    uint8_t dec_buf[128];
//    uint16_t dec_len;
//   
//    ike_encrypt_data(&test_ctx, msg, strlen((char*)msg), packet, &packet_len);
//    xil_printf("[INFO] T-EtM-01: Encrypted and MACed payload.\r\n");
//    
//    packet[20] ^= 0x01;
//    if(ike_decrypt_data(&test_ctx, packet, packet_len, dec_buf, &dec_len) != 0) {
//        xil_printf("[PASS] T-EtM-02: Tamper detected by HMAC (Security bit set).\r\n");
//    } else {
//         xil_printf("[FAIL] T-EtM-02: System failed to detect tampering!\r\n");
//    }
//    
//    packet[20] ^= 0x01;
//    if(ike_decrypt_data(&test_ctx, packet, packet_len, dec_buf, &dec_len) == 0) {
//        dec_buf[dec_len] = '\0';
//        xil_printf("[PASS] T-EtM-01: Authentication & Decryption Successful. Content: %s\r\n", dec_buf);
//    }
//    xil_printf("--- VERIFICATION COMPLETED ---\r\n\r\n");
//}

ike_context_t g_ike_ctx;

#define BOARD_A
//#define BOARD_B

#ifdef BOARD_A
    const char *local_ip = "192.168.1.10";
    uint32_t local_ip_int = 0x0A01A8C0; // 192.168.1.10
    const char *peer_ip = "192.168.1.11";
    uint32_t peer_ip_int = 0x0B01A8C0; // 192.168.1.11
    uint8_t local_mac[] = { 0x00, 0x0a, 0x35, 0x00, 0x01, 0x0A };
    ike_role_t role = IKE_ROLE_INITIATOR;
#else
    const char *local_ip = "192.168.1.11";
    uint32_t local_ip_int = 0x0B01A8C0; // 192.168.1.11
    const char *peer_ip = "192.168.1.10";
    uint32_t peer_ip_int = 0x0A01A8C0; // 192.168.1.10
    uint8_t local_mac[] = { 0x00, 0x0a, 0x35, 0x00, 0x01, 0x0B };
    ike_role_t role = IKE_ROLE_RESPONDER;
#endif

int main() {
    Xil_ICacheEnable();
    Xil_DCacheEnable();
    //run_verification(); // verify the function
    xil_printf("\r\n======================================\r\n");
    xil_printf("  IKE Crypto System - ZYNQ PS Backend \r\n");
    xil_printf("  Role: %s, IP: %s\r\n", (role == IKE_ROLE_INITIATOR) ? "Initiator" : "Responder", local_ip);
    xil_printf("======================================\r\n");

    sa_manager_init();
    xil_printf("[INFO] SA Manager initialized.\r\n");

    init_platform();

    xil_printf("[INFO] Initializing Network stack (lwIP)...\r\n");
    network_init(local_ip, local_mac); 
    platform_enable_interrupts();
    xil_printf("[INFO] Network stack initialized.\r\n");

    uint8_t psk[] = "mysecretkey";
    ike_init(&g_ike_ctx, role, psk, sizeof(psk)-1, local_ip_int, peer_ip_int);
    xil_printf("[INFO] IKE Engine initialized.\r\n");

    if (role == IKE_ROLE_INITIATOR) {
        uint8_t send_buf[1024];
        uint16_t send_len;
        if (ike_initiate(&g_ike_ctx, send_buf, &send_len) == 0) {
            xil_printf("[INFO] Initiating IKE exchange (Sending SA_PROPOSE)...\r\n");
            udp_send_data(send_buf, send_len);
        }
    }

    xil_printf("[INFO] Listening for IKE packets...\r\n");
    
    while(1) {
        network_poll();
    }

    Xil_DCacheDisable();
    Xil_ICacheDisable();
    return 0;
}
