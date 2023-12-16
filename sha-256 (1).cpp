#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <bitset>
#include <cstdint>
// Constants and functions from the pseudocode
constexpr uint32_t ROTR(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

constexpr uint32_t SHR(uint32_t x, uint32_t n) {
    return x >> n;
}

constexpr uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

constexpr uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

constexpr uint32_t Sigma0(uint32_t x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

constexpr uint32_t Sigma1(uint32_t x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

constexpr uint32_t sigma0(uint32_t x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

constexpr uint32_t sigma1(uint32_t x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

constexpr uint32_t addition(uint32_t a, uint32_t b) {
    return (a + b) % 0xFFFFFFFF;
}


std::string binary_rep(std::string input) {
    std::string b = "";
    for (char x : input) {
        // Convert each character to its 8-bit binary representation
        std::bitset<8> chars(x);
        
        // Append the binary representation to the result string
        b += chars.to_string();
    }
    return b;
}


// Main SHA-256 algorithm
std::string sha256(const std::string& input) {
    // Initialize hash values
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    // Constants from the pseudocode
    constexpr uint32_t K[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Pre-processing and padding
    std::string msg = binary_rep(input);
    uint64_t length = msg.length();
    //padding 1
    msg+='1';
    uint32_t k = (448 - (length + 1)%512 )%512;
    //padding 0's
    for (int j = 0; j < k; j++) {
        msg += '0';
    }
    //padding length in binary format (64 bits)
    std::bitset<64>length_bits(length);
    msg+=length_bits.to_string();


    // Processing each block
    for (size_t i = 0; i < msg.length(); i +=512) {

        //entire message is operated in blocks/parts
        std::string msg_part=msg.substr(i,512);

        uint32_t w[64];
        
        // Breaking block into 16 big-endian words
        for (int j = 0; j < 16; j++) {
            std::bitset<32> word(msg_part.substr(j*32,32));
            w[j] = word.to_ulong();
        }

        // Extending the first 16 words into the remaining 48 words
        for (int j = 16; j < 64; j++) {
            w[j] = addition(sigma1(w[j - 2]),addition( w[j - 7],addition(sigma0(w[j - 15]),w[j - 16])));
        }

        // Initializeing working variables
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        // Compression function main loop
        for (int j = 0; j < 64; j++) {
            uint32_t S1 = Sigma1(e);
            uint32_t ch = Ch(e, f, g);
            uint32_t temp1 = addition(h,addition(S1,addition(ch,addition(K[j],w[j]))));
            uint32_t S0 = Sigma0(a);
            uint32_t maj = Maj(a, b, c);
            uint32_t temp2 = addition(S0,maj);

            h = g;
            g = f;
            f = e;
            e = addition(d,temp1);
            d = c;
            c = b;
            b = a;
            a = addition(temp1,temp2);
        }

        // Add the compressed chunk to the current hash value
        h0 =addition(h0,a);
        h1 =addition(h1,b);
        h2 =addition(h2,c);
        h3 =addition(h3,d);
        h4 =addition(h4,e);
        h5 =addition(h5,f);
        h6 =addition(h6,g);
        h7 =addition(h7,h);
    }

    // Producing the final hash value (big-endian)
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << h0;
    ss << std::hex << std::setw(8) << std::setfill('0') << h1;
    ss << std::hex << std::setw(8) << std::setfill('0') << h2;
    ss << std::hex << std::setw(8) << std::setfill('0') << h3;
    ss << std::hex << std::setw(8) << std::setfill('0') << h4;
    ss << std::hex << std::setw(8) << std::setfill('0') << h5;
    ss << std::hex << std::setw(8) << std::setfill('0') << h6;
    ss << std::hex << std::setw(8) << std::setfill('0') << h7;

    return ss.str();
}

int main() {
    // Read input from the file
    std::ifstream file("bible.txt");
    if (!file.is_open()) {
        std::cerr << "Error opening file." << std::endl;
        return 1;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string input = buffer.str();

    // Close the file
    file.close();

    // Perform SHA-256 hashing
    std::string hash = sha256(input);

    // Display the results
    std::cout << "SHA-256 Hash for 'bible.txt': " << hash << std::endl;

    return 0;
}


// OUTPUT:
// SHA-256 Hash for 'bible.txt': 8d202adf39c3e88510a591cbe1cbd96708e3237140060c0768f2577f9d81d3ad

