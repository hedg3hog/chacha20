#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define KEY_STREAM_BYTE_LEN 64

uint32_t swap_endian32(uint32_t x) {
    return ((x & 0x000000FF) << 24) |
           ((x & 0x0000FF00) << 8)  |
           ((x & 0x00FF0000) >> 8)  |
           ((x & 0xFF000000) >> 24);
}

void u32_to_bytes(uint32_t value, uint8_t bytes[4]) {
    bytes[0] = (value >> 24) & 0xFF; // MSB
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >> 8)  & 0xFF;
    bytes[3] = (value >> 0)  & 0xFF; // LSB
}
uint32_t bytes_to_u32(const uint8_t bytes[4]) {
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8)  |
           ((uint32_t)bytes[3]);
}

uint32_t leftRotate(uint32_t n, unsigned int d)
{
    /* In n<<d, last d bits are 0. To put first 3 bits of n
       at last, do bitwise or of n<<d with n >>(INT_BITS -
       d) */
    return (n << d) | (n >> (32 - d));
}

/*Function to right rotate n by d bits*/
uint32_t rightRotate(uint32_t n, unsigned int d)
{
    /* In n>>d, first d bits are 0. To put last 3 bits of at
            first, do bitwise or of n>>d with n <<(INT_BITS
       - d) */
    return (n >> d) | (n << (32 - d));
}

void printstate(uint32_t teststate[16]){
    for (size_t i = 0; i < 4; i++)
    {
        size_t idx = i*4;
        printf("0x%08X;  0x%08X;  0x%08X;  0x%08X;  \n", teststate[idx], teststate[idx+1], teststate[idx+2], teststate[idx+3]);
    };
    printf("##############\n");
}

int quater_round(uint32_t *a,  uint32_t *b, uint32_t *c, uint32_t *d){
    *a += *b; 
    *d ^= *a; 
    *d = leftRotate(*d,16);
    *c += *d; 
    *b ^= *c; 
    *b = leftRotate(*b, 12);
    *a += *b; 
    *d ^= *a; 
    *d = leftRotate(*d ,8);
    *c += *d; 
    *b ^= *c; 
    *b = leftRotate(*b, 7);

    return 0;
}
uint32_t CHA_CHA_CONST[] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

typedef struct { uint32_t v[16]; } uint32_16_array_t;

void blockfunction(uint32_t state[16]) // 10*2 rounds
{
    for (size_t i = 0; i < 10; i++)
    {
    quater_round(&state[0], &state[4], &state[8], &state[12]);
    quater_round(&state[1], &state[5], &state[9], &state[13]);
    quater_round(&state[2], &state[6], &state[10], &state[14]);
    quater_round(&state[3], &state[7], &state[11], &state[15]);
    quater_round(&state[0], &state[5], &state[10], &state[15]);
    quater_round(&state[1], &state[6], &state[11], &state[12]);
    quater_round(&state[2], &state[7], &state[8], &state[13]);
    quater_round(&state[3], &state[4], &state[9], &state[14]);
    }
};

void chacha20_keystream(uint32_t key[8], uint32_t counter, uint32_t nonce[3], uint8_t keystream[KEY_STREAM_BYTE_LEN]){
    uint32_t state[16];
    size_t idx_offset = 0;

    // setup state: concat constants | key | counter | nonce
    // invert endianess of all except constants and counter

    for (size_t i = 0; i < 4; i++)
    {
        state[i+idx_offset] = CHA_CHA_CONST[i];
    };
    idx_offset +=4;

    for (size_t i = 0; i < 8; i++)
    {
        state[i+idx_offset] = swap_endian32(key[i]);
    };
    idx_offset +=8;

    state[idx_offset] = counter;
    idx_offset +=1;

    for (size_t i = 0; i < 3; i++)
    {
        state[i+idx_offset] = swap_endian32(nonce[i]);
    };
    // save initial state for later
    uint32_t initial_state[16];

    memcpy(initial_state, state, sizeof(state));

    // run the 20 rounds on state
    blockfunction(state);



    // create retrun struct
    uint32_16_array_t key_stream;
    // add initial state and convert endianess
    for (size_t i = 0; i < 16; i++)
    {
        uint8_t word_4x8[4];
        u32_to_bytes(swap_endian32(initial_state[i] + state [i]), word_4x8);
        for (size_t j = 0; j < 4; j++)
        {
            keystream[i*4 + j] = word_4x8[j];
        }
        

    }
};

void chacha20_enc(uint32_t key[8], uint32_t nonce[3],size_t n, uint8_t plaintext[n], uint8_t ciphertext[n]){
    size_t num_complete_blocks = n / KEY_STREAM_BYTE_LEN;
    size_t bytes_left = n % KEY_STREAM_BYTE_LEN;
    uint32_t counter = 0;
    printf("%d %d %d \n\n", (uint32_t)num_complete_blocks, (uint32_t)bytes_left, counter);
    for (size_t i = 0; i < num_complete_blocks; i++)
    {   
        counter = (uint32_t)i + 1; // counter starts at 1
        uint8_t keystream[KEY_STREAM_BYTE_LEN];
        size_t offset = KEY_STREAM_BYTE_LEN * i;
        chacha20_keystream(key, counter, nonce, keystream);
        for (size_t j = 0; j < KEY_STREAM_BYTE_LEN; j++) // for all keystream bytes
        {
            ciphertext[offset+j] = plaintext[offset+j] ^ keystream[j];
        }
    }
    if (bytes_left > 0){
        counter += 1;
        size_t offset = KEY_STREAM_BYTE_LEN * ((size_t)counter -1 );
        uint8_t keystream[KEY_STREAM_BYTE_LEN];
        chacha20_keystream(key, counter, nonce, keystream);

        for (size_t i = 0; i < bytes_left; i++)
        {
            ciphertext[offset+i] = plaintext[offset+i] ^ keystream[i];
        }
        
    }
    
}




int main(int argc, char const *argv[])
{
    uint32_t key[8]= {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f}; 
    uint32_t counter = 0x00000001; 
    uint32_t nonce[3] = {0x00000000, 0x0000004a, 0x00000000};
    uint8_t plaintext[]= {0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 
0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, 
0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 
0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, 
0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 
0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 
0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 
0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 
0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 
0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 
0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 
0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 
0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 
0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 
0x74, 0x2e, };
    size_t plaintext_len = sizeof(plaintext);
    uint8_t ciphertext[plaintext_len];
    chacha20_enc(key, nonce, plaintext_len, plaintext, ciphertext);

    for (size_t i = 0; i < plaintext_len; i++)
    {
        printf("%02X ", ciphertext[i]);
        if ((i+1)%16 == 0){
            printf("\n");
        } 
    }
    printf("\n");
    
    return 0;
}
