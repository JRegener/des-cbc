#include "descrypt.h"

DESCrypt::DESCrypt()
{

}

int32_t
DESCrypt::start(uint8_t * input, uint32_t size_input, uint8_t ** output, int32_t & add_bits)
{
    return div_64bit(input, size_input, output, add_bits);
}

int32_t
DESCrypt::startDecrypt(uint8_t * input, uint32_t size_input, uint8_t ** output,const int32_t & add_bits)
{
    return div_64bitDecrypt(input,size_input,output, add_bits);
}

void
DESCrypt::test(){
    uint8_t test_block[8] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
    uint8_t test_key[8] = "1234567";
    uint8_t test_result[8] = {0};

    print_bits_to_line(test_block, 8, "coding mess");

    generate_keys(test_key);

    crypt(test_block, test_result);
    print_bits_to_line(test_result, 8, "crypt");

    decrypt(test_result, test_block);
    print_bits_to_line(test_block, 8, "decrypt");
}

void
DESCrypt::print_bits_to_line(uint8_t out[], uint32_t n, const char* name) {
    std::cout << name << std::endl;
    for (uint32_t i = 0; i < n; i++) {
        std::bitset<8> tmp{ out[i] };
        std::cout << tmp << " ";
    }
    std::cout << std::endl;
}

void
DESCrypt::crypt(uint8_t block[], uint8_t result[])
{
    // Начальная перестановка
    uint8_t block_IP[8];
    permutation(std::begin(IP), std::end(IP), block, block_IP, 8);

    uint8_t block_L[4] = {block_IP[0],block_IP[1],block_IP[2],block_IP[3]};
    uint8_t block_R[4] = {block_IP[4],block_IP[5],block_IP[6],block_IP[7]};

    uint8_t block_E[6];
    uint8_t sboxes_block[4];
    uint8_t block_P[4];


    for(uint32_t i = 0; i < 16; i++){
        //расширение block_R до 48 бит
        permutation(std::begin(E), std::end(E), block_R, block_E, 6);
        //XOR с ключом
        XOR(block_E, keys[i], 6);
        //S-boxes
        SBoxes(block_E, sboxes_block);
        //перестановка P
        permutation(std::begin(P), std::end(P), sboxes_block, block_P, 4);
        //XOR с блоком L
        XOR(block_P, block_L, 4);
        //Заполнение L
        block_L[0] = block_R[0];
        block_L[1] = block_R[1];
        block_L[2] = block_R[2];
        block_L[3] = block_R[3];

        //Заполнение R
        block_R[0] = block_P[0];
        block_R[1] = block_P[1];
        block_R[2] = block_P[2];
        block_R[3] = block_P[3];
    }


    for(uint32_t i = 0; i < 4; i++){
        block[i] = block_L[i];
    }
    for(uint32_t i = 0; i < 4; i++){
        block[i+4] = block_R[i];
    }

    permutation(std::begin(IP_INV), std::end(IP_INV), block, result, 8);
}

void
DESCrypt::decrypt(uint8_t block[], uint8_t result[])
{
    // Начальная перестановка
    uint8_t block_IP[8];
    permutation(std::begin(IP), std::end(IP), block, block_IP, 8);

    uint8_t block_L[4] = {block_IP[0],block_IP[1],block_IP[2],block_IP[3]};
    uint8_t block_R[4] = {block_IP[4],block_IP[5],block_IP[6],block_IP[7]};

    uint8_t block_E[6];
    uint8_t sboxes_block[4];
    uint8_t block_P[4];


    for(int32_t i = 15; i >= 0; i--){
        //расширение block_R до 48 бит
        //E перевернута
        permutation(std::begin(E), std::end(E), block_L, block_E, 6);
        //XOR с ключом
        XOR(block_E, keys[i], 6);
        //S-boxes
        SBoxes(block_E, sboxes_block);
        //перестановка P
        permutation(std::begin(P), std::end(P), sboxes_block, block_P, 4);
        //XOR с блоком L
        XOR(block_P, block_R, 4);
        //Заполнение L
        block_R[0] = block_L[0];
        block_R[1] = block_L[1];
        block_R[2] = block_L[2];
        block_R[3] = block_L[3];

        //Заполнение R
        block_L[0] = block_P[0];
        block_L[1] = block_P[1];
        block_L[2] = block_P[2];
        block_L[3] = block_P[3];
    }

    for(uint32_t i = 0; i < 4; i++){
        block[i] = block_L[i];
    }
    for(uint32_t i = 0; i < 4; i++){
        block[i+4] = block_R[i];
    }

    permutation(std::begin(IP_INV), std::end(IP_INV), block, result, 8);
}

int32_t
DESCrypt::div_64bitDecrypt(uint8_t * input, uint32_t size_input, uint8_t ** output, const int32_t & add_bits)
{
    uint32_t count_blocks = size_input / 8;
    uint8_t block[8] = {0};
    uint8_t C_0[8] = {0};
    uint8_t result[8] = {0};

    uint32_t output_size = size_input - add_bits;
    *output = new uint8_t[output_size];
    uint32_t output_cur_index = 0;

    C_0[0] = IV[0];
    C_0[1] = IV[1];
    C_0[2] = IV[2];
    C_0[3] = IV[3];
    C_0[4] = IV[4];
    C_0[5] = IV[5];
    C_0[6] = IV[6];
    C_0[7] = IV[7];

    for(uint32_t i = 0; i < count_blocks; i++){
        block[0] = input[i * 8 + 0];
        block[1] = input[i * 8 + 1];
        block[2] = input[i * 8 + 2];
        block[3] = input[i * 8 + 3];
        block[4] = input[i * 8 + 4];
        block[5] = input[i * 8 + 5];
        block[6] = input[i * 8 + 6];
        block[7] = input[i * 8 + 7];

        decrypt(block, result);

        XOR(result, C_0, 8);

        (*output)[output_cur_index * 8 + 0] = result[0];
        (*output)[output_cur_index * 8 + 1] = result[1];
        (*output)[output_cur_index * 8 + 2] = result[2];
        (*output)[output_cur_index * 8 + 3] = result[3];
        (*output)[output_cur_index * 8 + 4] = result[4];
        (*output)[output_cur_index * 8 + 5] = result[5];
        (*output)[output_cur_index * 8 + 6] = result[6];
        (*output)[output_cur_index * 8 + 7] = result[7];

        output_cur_index++;

        C_0[0] = input[i * 8 + 0];
        C_0[1] = input[i * 8 + 1];
        C_0[2] = input[i * 8 + 2];
        C_0[3] = input[i * 8 + 3];
        C_0[4] = input[i * 8 + 4];
        C_0[5] = input[i * 8 + 5];
        C_0[6] = input[i * 8 + 6];
        C_0[7] = input[i * 8 + 7];

//        memset(block, 0, sizeof(block));
        memset(result, 0, sizeof(result));
    }

    return output_size;
}

int32_t
DESCrypt::div_64bit(uint8_t * input, uint32_t size_input, uint8_t ** output, int32_t & add_bits)
{
    uint32_t count_blocks = size_input / 8;
    uint32_t reminder_size = size_input % 8;
    uint8_t block[8] = {0};
    uint8_t result[8] = {0};

    uint32_t output_size = reminder_size == 0 ? size_input : size_input + 8 - reminder_size;
    add_bits = reminder_size == 0 ? 0 : (8 - reminder_size);

    *output = new uint8_t[output_size];
    uint32_t output_cur_index = 0;

    block[0] = IV[0];
    block[1] = IV[1];
    block[2] = IV[2];
    block[3] = IV[3];
    block[4] = IV[4];
    block[5] = IV[5];
    block[6] = IV[6];
    block[7] = IV[7];

    for(uint32_t i = 0; i < count_blocks; i++){
        result[0] = input[i * 8 + 0];
        result[1] = input[i * 8 + 1];
        result[2] = input[i * 8 + 2];
        result[3] = input[i * 8 + 3];
        result[4] = input[i * 8 + 4];
        result[5] = input[i * 8 + 5];
        result[6] = input[i * 8 + 6];
        result[7] = input[i * 8 + 7];

        XOR(block, result, 8);

        crypt(block, result);

        (*output)[output_cur_index * 8 + 0] = result[0];
        (*output)[output_cur_index * 8 + 1] = result[1];
        (*output)[output_cur_index * 8 + 2] = result[2];
        (*output)[output_cur_index * 8 + 3] = result[3];
        (*output)[output_cur_index * 8 + 4] = result[4];
        (*output)[output_cur_index * 8 + 5] = result[5];
        (*output)[output_cur_index * 8 + 6] = result[6];
        (*output)[output_cur_index * 8 + 7] = result[7];

        output_cur_index++;

        block[0] = result[0];
        block[1] = result[1];
        block[2] = result[2];
        block[3] = result[3];
        block[4] = result[4];
        block[5] = result[5];
        block[6] = result[6];
        block[7] = result[7];

//        memset(block, 0, sizeof(block));
        memset(result, 0, sizeof(result));
    }


    if (reminder_size != 0) {
        for(uint32_t i = 0; i < reminder_size; i++){
            result[i] = input[count_blocks * 8 + i];
        }

        XOR(result, block, 8);
        crypt(block, result);

        (*output)[output_cur_index * 8 + 0] = result[0];
        (*output)[output_cur_index * 8 + 1] = result[1];
        (*output)[output_cur_index * 8 + 2] = result[2];
        (*output)[output_cur_index * 8 + 3] = result[3];
        (*output)[output_cur_index * 8 + 4] = result[4];
        (*output)[output_cur_index * 8 + 5] = result[5];
        (*output)[output_cur_index * 8 + 6] = result[6];
        (*output)[output_cur_index * 8 + 7] = result[7];

        output_cur_index++;
    }

    return output_size;
}

void
DESCrypt::generate_keys(uint8_t * base_key)
{
    //усечение ключа
    uint8_t k_G[8];
    permutation(std::begin(key_G), std::end(key_G), base_key, k_G, 7);

    uint8_t key_C[4];
    uint8_t key_D[4];
    for(size_t i = 0; i < 4; i++){
        key_C[i] = k_G[i];
    }
    key_C[3] &= 0xF0;

    uint8_t mask = 0xF0;
    key_D[0] = k_G[3] << 4;
    key_D[0] |= (k_G[4] & mask) >> 4;
    key_D[1] = k_G[4] << 4;
    key_D[1] |= (k_G[5] & mask) >> 4;
    key_D[2] = k_G[5] << 4;
    key_D[2] |= (k_G[6] & mask) >> 4;
    key_D[3] = k_G[6] << 4;

    uint8_t buf_key[7];
    uint8_t compress_key[6];

    for(int32_t i = 0; i < 16; i++){
        for(int32_t j = 0; j < key_shift[i]; j++){
            left_shift_key(key_C, 4);
            left_shift_key(key_D, 4);
        }

        for(size_t j = 0; j < 4; j++){
            buf_key[j] = key_C[j];
        }

        buf_key[3] |= (key_D[0] & mask) >> 4;
        buf_key[4] = key_D[0] << 4;
        buf_key[4] |= (key_D[1] & mask) >> 4;
        buf_key[5] = key_D[1] << 4;
        buf_key[5] |= (key_D[2] & mask) >> 4;
        buf_key[6] = key_D[2] << 4;
        buf_key[6] |= (key_D[3] & mask) >> 4;

        permutation(std::begin(key_K),std::end(key_K), buf_key, compress_key, 6);

        keys[i][0] = compress_key[0];
        keys[i][1] = compress_key[1];
        keys[i][2] = compress_key[2];
        keys[i][3] = compress_key[3];
        keys[i][4] = compress_key[4];
        keys[i][5] = compress_key[5];
    }
}

void
DESCrypt::left_shift_key(uint8_t key_block[], int32_t size)
{
    uint8_t buf_first = 0;
    uint8_t buf_last = (key_block[size - 1] & option8) >> 7;
    key_block[size - 1] <<= 1;
    key_block[size - 1] |= (key_block[0] & option8) >> 3;

    for(int32_t i = size - 2; i >= 0; i--){
        buf_first = (key_block[i] & option8) >> 7;
        key_block[i] <<= 1;
        key_block[i] |= buf_last;
        buf_last = buf_first;
    }
}

void
DESCrypt::SBoxes(uint8_t block_E[], uint8_t output[])
{
    const uint8_t four_bit_mask = 0x0F; // 00001111
    const uint8_t mask1 = 0xFC; //11111100 6
    const uint8_t mask2 = 0x03; //00000011 2

    const uint8_t mask3 = 0xF0; //11110000 4
    const uint8_t mask4 = 0x0F; //00001111 4

    const uint8_t mask5 = 0xC0; //11000000 2
    const uint8_t mask6 = 0x3F; //00111111 6

    uint8_t six_bit_block;
    uint8_t row_id;
    uint8_t colomn_id;
    //S1
    six_bit_block = (block_E[0] & mask1) >> 2;
    row_id = ((six_bit_block & option6) >> 4) | (six_bit_block & option1);
    colomn_id = (six_bit_block >> 1) & four_bit_mask;
    output[0] = S1[row_id][colomn_id] << 4;
    //S2
    six_bit_block = ((block_E[0] & mask2) << 4) | ((block_E[1] & mask3) >> 4);
    row_id = ((six_bit_block & option6) >> 4) | (six_bit_block & option1);
    colomn_id = (six_bit_block >> 1) & four_bit_mask;
    output[0] |= S2[row_id][colomn_id];
    //S3
    six_bit_block = ((block_E[1] & mask4) << 2) | ((block_E[2] & mask5) >> 6);
    row_id = ((six_bit_block & option6) >> 4) | (six_bit_block & option1);
    colomn_id = (six_bit_block >> 1) & four_bit_mask;
    output[1] = S3[row_id][colomn_id] << 4;
    //S4
    six_bit_block = block_E[2] & mask6;
    row_id = ((six_bit_block & option6) >> 4) | (six_bit_block & option1);
    colomn_id = (six_bit_block >> 1) & four_bit_mask;
    output[1] |= S4[row_id][colomn_id];

    //S5
    six_bit_block = (block_E[3] & mask1) >> 2;
    row_id = ((six_bit_block & option6) >> 4) | (six_bit_block & option1);
    colomn_id = (six_bit_block >> 1) & four_bit_mask;
    output[2] = S5[row_id][colomn_id] << 4;
    //S6
    six_bit_block = ((block_E[3] & mask2) << 4) | ((block_E[4] & mask3) >> 4);
    row_id = ((six_bit_block & option6) >> 4) | (six_bit_block & option1);
    colomn_id = (six_bit_block >> 1) & four_bit_mask;
    output[2] |= S6[row_id][colomn_id];
    //S7
    six_bit_block = ((block_E[4] & mask4) << 2) | ((block_E[5] & mask5) >> 6);
    row_id = ((six_bit_block & option6) >> 4) | (six_bit_block & option1);
    colomn_id = (six_bit_block >> 1) & four_bit_mask;
    output[3] = S7[row_id][colomn_id] << 4;
    //S8
    six_bit_block = block_E[5] & mask6;
    row_id = ((six_bit_block & option6) >> 4) | (six_bit_block & option1);
    colomn_id = (six_bit_block >> 1) & four_bit_mask;
    output[4] |= S8[row_id][colomn_id];
}

void
DESCrypt::XOR(uint8_t a[], uint8_t b[], size_t size)
{
    for(size_t i = 0; i < size; i++){
        a[i] = a[i] ^ b[i];
    }
}

void
DESCrypt::permutation(const int32_t * begin, const int32_t * end, const uint8_t * input,
                           uint8_t * output, int32_t output_size){
    uint32_t block_num = 0;
    uint32_t bit_num = 0;
    uint8_t first_bit = 0;

    uint8_t buf_first = 0;
    uint8_t buf_last = 0;

    memset(output, 0, output_size);

    for (auto ptr = begin; ptr != end; ptr++) {
        block_num = (*ptr - 1) / 8;
        bit_num = (*ptr - 1) % 8;

        first_bit = input[block_num] << bit_num;
        first_bit = first_bit & option8;

        buf_first = 0;
        buf_last = (output[output_size - 1] & option8) >> 7;
        output[output_size - 1] <<= 1;
        output[output_size - 1] |= first_bit >> 7;

        for(int32_t i = output_size - 2; i >= 0; i--){
            buf_first = (output[i] & option8) >> 7;
            output[i] <<= 1;
            output[i] |= buf_last;
            buf_last = buf_first;
        }

    }
}
