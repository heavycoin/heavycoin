//  CXXFLAGS="-I /opt/local/include" LDFLAGS="-I /opt/local/lib" g++ -I /opt/local/include -g genkeys.cpp -o genkeys obj/hefty1.o obj/keccak.o obj/blake.o obj/groestl.o /opt/local/lib/libssl.a /opt/local/lib/libcrypto.a  /opt/local/lib/libboost_system-mt.a  /opt/local/lib/libz.a -a
// g++ -g genkeys.cpp -o genkeys obj/hefty1.o obj/keccak.o obj/blake.o obj/groestl.o -lssl -lcrypto -lboost_system
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ripemd.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <assert.h>

#include <vector>
#include <algorithm>
#include <string.h>

#include "bignum.h"
#include "hash.h"

#define ECDSA_PUBKEY_DIGEST_LENGTH  65

//Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresse
#define PRIVATE_KEY_HEAVYCOIN_BYTE 128
#define PUBLIC_KEY_HEAVYCOIN_BYTE 40

unsigned char pubKeybn[ECDSA_PUBKEY_DIGEST_LENGTH+2];

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Encode a byte sequence as a base58-encoded string
inline std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    CAutoBN_CTX pctx;
    CBigNum bn58 = 58;
    CBigNum bn0 = 0;

    // Convert big endian data to little endian
    // Extra zero at the end make sure bignum will interpret as a positive number
    std::vector<unsigned char> vchTmp(pend-pbegin+1, 0);
    reverse_copy(pbegin, pend, vchTmp.begin());

    // Convert little endian data to bignum
    CBigNum bn;
    bn.setvch(vchTmp);

    // Convert bignum to std::string
    std::string str;
    // Expected size increase from base58 conversion is approximately 137%
    // use 138% to be safe
    str.reserve((pend - pbegin) * 138 / 100 + 1);
    CBigNum dv;
    CBigNum rem;
    while (bn > bn0)
    {
        if (!BN_div(&dv, &rem, &bn, &bn58, pctx))
            throw bignum_error("EncodeBase58 : BN_div failed");
        bn = dv;
        unsigned int c = rem.getulong();
        str += pszBase58[c];
    }

    // Leading zeroes encoded as base58 zeros
    for (const unsigned char* p = pbegin; p < pend && *p == 0; p++)
        str += pszBase58[0];

    // Convert little endian std::string to big endian
    reverse(str.begin(), str.end());
    return str;
}

// Encode a byte vector as a base58-encoded string
inline std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

// Decode a base58-encoded string psz into byte vector vchRet
std::vector<unsigned char> DecodeBase58(const char* psz)
{
    std::vector<unsigned char> vchRet;

    CAutoBN_CTX pctx;
    vchRet.clear();
    CBigNum bn58 = 58;
    CBigNum bn = 0;
    CBigNum bnChar;
    while (isspace(*psz))
        psz++;

    // Convert big endian string to bignum
    for (const char* p = psz; *p; p++)
    {
        const char* p1 = strchr(pszBase58, *p);
        if (p1 == NULL)
        {
            while (isspace(*p))
                p++;
            if (*p != '\0')
                //return false;
                return vchRet;
            break;
        }
        bnChar.setulong(p1 - pszBase58);
        if (!BN_mul(&bn, &bn, &bn58, pctx))
            throw bignum_error("DecodeBase58 : BN_mul failed");
        bn += bnChar;
    }

    // Get bignum as little endian data
    std::vector<unsigned char> vchTmp = bn.getvch();

    // Trim off sign byte if present
    if (vchTmp.size() >= 2 && vchTmp.end()[-1] == 0 && vchTmp.end()[-2] >= 0x80)
        vchTmp.erase(vchTmp.end()-1);

    // Restore leading zeros
    int nLeadingZeros = 0;
    for (const char* p = psz; *p == pszBase58[0]; p++)
        nLeadingZeros++;
    vchRet.assign(nLeadingZeros + vchTmp.size(), 0);

    // Convert little endian data to big endian
    reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
    return vchRet;
}

// Decode a base58-encoded string str into byte vector vchRet
std::string DecodeBase58(const std::string& str)
{
    std::vector<unsigned char> vchRet = DecodeBase58(str.c_str());
    return std::string((const char*)&vchRet[0], vchRet.size());
}

// Decode a base64-encoded string str into byte vector vchRet
std::vector<unsigned char> DecodeBase64(const char* p, bool* pfInvalid)
{
    static const int decode64_table[256] =
    {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
        -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    };

    if (pfInvalid)
        *pfInvalid = false;

    std::vector<unsigned char> vchRet;
    vchRet.reserve(strlen(p)*3/4);

    int mode = 0;
    int left = 0;

    while (1)
    {
         int dec = decode64_table[(unsigned char)*p];
         if (dec == -1) break;
         p++;
         switch (mode)
         {
             case 0: // we have no bits and get 6
                 left = dec;
                 mode = 1;
                 break;

              case 1: // we have 6 bits and keep 4
                  vchRet.push_back((left<<2) | (dec>>4));
                  left = dec & 15;
                  mode = 2;
                  break;

             case 2: // we have 4 bits and get 6, we keep 2
                 vchRet.push_back((left<<4) | (dec>>2));
                 left = dec & 3;
                 mode = 3;
                 break;

             case 3: // we have 2 bits and get 6
                 vchRet.push_back((left<<6) | dec);
                 mode = 0;
                 break;
         }
    }

    if (pfInvalid)
        switch (mode)
        {
            case 0: // 4n base64 characters processed: ok
                break;

            case 1: // 4n+1 base64 character processed: impossible
                *pfInvalid = true;
                break;

            case 2: // 4n+2 base64 characters processed: require '=='
                if (left || p[0] != '=' || p[1] != '=' || decode64_table[(unsigned char)p[2]] != -1)
                    *pfInvalid = true;
                break;

            case 3: // 4n+3 base64 characters processed: require '='
                if (left || p[0] != '=' || decode64_table[(unsigned char)p[1]] != -1)
                    *pfInvalid = true;
                break;
        }

    return vchRet;
}

// Decode a base64-encoded string str into string
std::string DecodeBase64(const std::string& str)
{
    std::vector<unsigned char> vchRet = DecodeBase64(str.c_str());
    return std::string((const char*)&vchRet[0], vchRet.size());
}

// Encode bytes to hex string
std::string ToHex(const unsigned char* start, const unsigned char* end)
{
    std::stringstream ss;
    for(int i = 0; i < end-start; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)start[i];
    }
    return ss.str();
}

// Encode bytes to hex string
std::string ToHex(std::vector<unsigned char> str)
{
    return ToHex(&str.begin()[0], &str.begin()[0] + str.size());
}

std::vector<unsigned char> sha256(const std::vector<unsigned char> data)
{
    uint256 digest;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &data.begin()[0], data.size());
    SHA256_Final((unsigned char*)&digest, &ctx);
    return std::vector<unsigned char>(digest.begin(), digest.end());
}

std::vector<unsigned char> sha256(const std::string data)
{
    uint256 digest;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.c_str(), data.size());
    SHA256_Final((unsigned char*)&digest, &ctx);
    return std::vector<unsigned char>(digest.begin(), digest.end());
}

std::vector<unsigned char> sha256(const unsigned char *begin, const unsigned char *end)
{
    return sha256(std::vector<unsigned char>(begin, end));
}

// Return Private Key in Wallet Import format as vector<unsigned char>
// WIF = PRIVATE_KEY_HEAVYCOIN_BYTE + Hash(secret) + 4 byte checksum (take first 4 bytes from Hash(PRIVATE_KEY_HEAVYCOIN_BYTE + Hash(secret)) )
std::vector<unsigned char> getPrivateKeyWIF(std::vector<unsigned char> secret)
{
    uint256 digest = Hash(secret.begin(), secret.end());

    std::vector<unsigned char> vch(1, PRIVATE_KEY_HEAVYCOIN_BYTE);
    vch.insert(vch.end(), digest.begin(), digest.end());

    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return vch;
}

// Generate ECDSA public key from vchSecret
// vchSecret = Hash(secret)
void EC_KEY_generate_pubkey(const std::vector<unsigned char> &vchSecret)
{
    int error = 0;
//    int ok = 0;

    BIGNUM *bn = NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;
    EC_KEY *pkey = NULL;
    const EC_GROUP *group = NULL;

    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL)
    {
        std::cerr << "EC_KEY_new_by_curve_name failed" << std::endl;
        error = 1;
        goto err;
    }

    if (vchSecret.size() != 32)
    {
        std::cerr << "secret must be 32 bytes" << std::endl;
        error = 1;
        goto err;
    }

    // priv_key in BN
    bn = BN_bin2bn(&vchSecret[0],32,BN_new());

    if (bn == NULL)
    {
        std::cerr << "BN_bin2bn failed" << std::endl;
        error = 1;
        goto err;
    }

    group = EC_KEY_get0_group(pkey);
    if (group == NULL)
    {
        std::cerr << "EC_KEY_get0_group failed" << std::endl;
        error = 1;
        goto err;
    }

    if ((ctx = BN_CTX_new()) == NULL)
    {
        std::cerr << "BN_CTX_new failed" << std::endl;
        error = 1;
        goto err;
    }

    pub_key = EC_POINT_new(group);

    if (pub_key == NULL)
    {
        std::cerr << "EC_POINT_new failed" << std::endl;
        error = 1;
        goto err;
    }

    if (!EC_POINT_mul(group, pub_key, bn, NULL, NULL, ctx))
    {
        std::cerr << "EC_POINT_mul failed" << std::endl;
        error = 1;
        goto err;
    }

    EC_KEY_set_private_key(pkey,bn);
    EC_KEY_set_public_key(pkey,pub_key);

    BIGNUM pubKeyBN;
    BN_init(&pubKeyBN);

    EC_POINT_point2bn(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, &pubKeyBN, ctx);
    BN_bn2bin((const BIGNUM*)&pubKeyBN, pubKeybn);

err:

    if (pub_key != NULL)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    if (bn != NULL)
        BN_clear_free(bn);

    if (error != 0)
        abort();
}

// Get address
// Address = PUBLIC_KEY_HEAVYCOIN_BYTE + Hash160(ECDSAPubKey) + 4 byte checksum
// ECDSAPubKey = EC_KEY_generate_pubkey(Hash(secret))
// checksum = first 4 bytes from Hash(PUBLIC_KEY_HEAVYCOIN_BYTE + Hash160(ECDSAPubKey))
std::vector<unsigned char> getAddress(const std::vector<unsigned char> &vchSecret)
{
    // omit 1st byte
    std::vector<unsigned char> secret(vchSecret.begin()+1, vchSecret.begin() + 1 + 32);

    // generate ECDSA public key from secret
    EC_KEY_generate_pubkey(secret);

    std::vector<unsigned char> ECDSAPubKey(pubKeybn, pubKeybn+ECDSA_PUBKEY_DIGEST_LENGTH);

    uint160 digest160 = Hash160(ECDSAPubKey);

    std::vector<unsigned char> vch(1, PUBLIC_KEY_HEAVYCOIN_BYTE);
    vch.insert(vch.end(), digest160.begin(), digest160.end());

    // add 4-byte hash check to the end
    std::vector<unsigned char> vch2(vch);
    uint256 hash = Hash(vch2.begin(), vch2.end());

    vch2.insert(vch2.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return vch2;
}

static int decodeBase58flag = 0;
static int decodeBase64flag = 0;
static int brainWallet = 0;
static char *pvalue = NULL;

void parseOpt(int argc, char **argv)
{
       int c;

       while (1)
         {
           static struct option long_options[] =
             {
               /* These options set a flag. */
               /* These options don't set a flag.
                  We distinguish them by their indices. */
               {"dec58",  required_argument, 0, 'd'},
               {"dec64",  required_argument, 0, 'e'},
               {"phrase",  required_argument, 0, 'p'},
               {0, 0, 0, 0}
             };
           /* getopt_long stores the option index here. */
           int option_index = 0;
           c = getopt_long (argc, argv, "",
                            long_options, &option_index);

           /* Detect the end of the options. */
           if (c == -1)
             break;

           switch (c)
             {
             case 0:
               /* If this option set a flag, do nothing else now. */
               if (long_options[option_index].flag != 0)
                 break;
               if (optarg)
                 break;
             case 'd':
               decodeBase58flag = 1;
               pvalue = optarg;
               break;
             case 'e':
               decodeBase64flag = 1;
               pvalue = optarg;
               break;
             case 'p':
               brainWallet = 1;
               pvalue = optarg;
               break;
             case '?':
               /* getopt_long already printed an error message. */
               break;

             default:
               abort ();
             }
         }
}

int main(int argc, char **argv)
{
    parseOpt(argc, argv);

    // --dec58 option. Decode Base58 and print hex
    if (decodeBase58flag)
    {
        std::cout << ToHex(DecodeBase58(pvalue)) << std::endl;
        return 0;
    }
    // --dec64 option. Decode Base64 and print hex
    if (decodeBase64flag)
    {
        std::cout << ToHex(DecodeBase64(pvalue)) << std::endl;
        return 0;
    }

    std::vector<unsigned char> secret;

    if (!brainWallet)
    {
        // get random bytes
        unsigned char rand[1024] = { };
        if (!RAND_bytes(rand, sizeof(rand)))
        {
            std::cerr << "Unable to get cryptographically strong pseudo-random bytes" << std::endl;
            return 1;
        }
        secret = sha256(rand, rand + sizeof(rand));
    }
    else
    {
        std::string phrase(pvalue);
        secret = sha256(phrase);
    }

    // generate Private Key in Wallet Import Format and Heavycoin address (Public Key)
    std::vector<unsigned char> PrivateKeyWIF = getPrivateKeyWIF(secret);
    std::vector<unsigned char> Address = getAddress(PrivateKeyWIF);

    std::cout << std::endl;
    std::cout << "Heavycoin Private Key:\t" << EncodeBase58(PrivateKeyWIF) << std::endl;
    std::cout << "Heavycoin Public Key:\t" << ToHex(pubKeybn, pubKeybn + ECDSA_PUBKEY_DIGEST_LENGTH) << std::endl;
    std::cout << "Heavycoin Address:\t" << EncodeBase58(Address) << std::endl;
    std::cout << std::endl;

    return 0;
}
