








#ifndef IKE_PROTOCOL_H
#define IKE_PROTOCOL_H

#include <stdint.h>






#define IKE_PORT 500


#define DH_KEY_LEN 256   


#define AES_KEY_LEN    16   
#define HMAC_KEY_LEN   20   
#define NONCE_LEN      16   
#define HASH_LEN       20   


typedef enum {
    IKE_STATE_IDLE = 0,
    IKE_STATE_SA_INIT,       
    IKE_STATE_SA_AGREED,     
    IKE_STATE_KE_SENT,       
    IKE_STATE_KE_DONE,       
    IKE_STATE_AUTH_SENT,     
    IKE_STATE_ESTABLISHED,   
    IKE_STATE_ERROR          
} ike_state_t;


typedef enum {
    IKE_ROLE_INITIATOR = 0,
    IKE_ROLE_RESPONDER
} ike_role_t;


typedef enum {
    IKE_MSG_SA_PROPOSE  = 1,  
    IKE_MSG_SA_ACCEPT   = 2,  
    IKE_MSG_KE_NONCE    = 3,  
    IKE_MSG_AUTH        = 5,  
    IKE_MSG_DATA        = 10, 
    IKE_MSG_ERROR       = 99  
} ike_msg_type_t;




typedef struct {
    uint32_t spi;                        
    uint8_t  enc_key[AES_KEY_LEN];       
    uint8_t  auth_key[HMAC_KEY_LEN];     
    uint8_t  iv[AES_KEY_LEN];            
    uint32_t peer_ip;                    
    ike_state_t state;                   
} sa_entry_t;




typedef struct {
    ike_role_t  role;                     
    ike_state_t state;                   

    uint8_t     cky_i[8];               
    uint8_t     cky_r[8];               

    uint8_t     dh_private[DH_KEY_LEN];  
    uint8_t     dh_public[DH_KEY_LEN];   
    uint8_t     dh_peer_pub[DH_KEY_LEN]; 
    uint8_t     dh_shared[DH_KEY_LEN];   

    uint8_t     nonce_i[NONCE_LEN];      
    uint8_t     nonce_r[NONCE_LEN];      

    uint8_t     psk[32];                 
    uint8_t     psk_len;

    uint8_t     skeyid[HASH_LEN];        
    uint8_t     skeyid_d[HASH_LEN];      
    uint8_t     skeyid_a[HASH_LEN];      
    uint8_t     skeyid_e[HASH_LEN];      

    sa_entry_t  sa;

    uint32_t    local_ip;
    uint32_t    peer_ip;
    uint16_t    local_port;
    uint16_t    peer_port;
} ike_context_t;





typedef struct __attribute__((packed)) {
    uint8_t  msg_type;                   
    uint8_t  reserved;
    uint16_t payload_len;                
    uint8_t  cky_i[8];                   
    uint8_t  cky_r[8];                   
} ike_header_t;








void ike_init(ike_context_t *ctx, ike_role_t role,
              const uint8_t *psk, uint8_t psk_len,
              uint32_t local_ip, uint32_t peer_ip);





int ike_initiate(ike_context_t *ctx);









int ike_process_message(ike_context_t *ctx,
                        const uint8_t *data, uint16_t data_len,
                        uint8_t *resp, uint16_t *resp_len);








int ike_encrypt_data(ike_context_t *ctx,
                     const uint8_t *plaintext, uint16_t plain_len,
                     uint8_t *ciphertext, uint16_t *cipher_len);




int ike_decrypt_data(ike_context_t *ctx,
                     const uint8_t *ciphertext, uint16_t cipher_len,
                     uint8_t *plaintext, uint16_t *plain_len);




void ike_derive_keys(ike_context_t *ctx);

#endif 
