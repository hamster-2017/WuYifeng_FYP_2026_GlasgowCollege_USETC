




#ifndef SA_MANAGER_H
#define SA_MANAGER_H

#include "ike_protocol.h"

void sa_manager_init(void);
sa_entry_t* sa_alloc(void);
sa_entry_t* sa_find_by_spi(uint32_t spi);
sa_entry_t* sa_find_by_ip(uint32_t ip);

#endif 
