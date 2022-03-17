//
//  galois_counter.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

// Abridged from
// https://github.com/michaeljclark/aes-gcm/blob/master/src/aes-gcm.c
// I added a GCM cipher because Chrome does not support CBC ciphers.


#include "galois_counter.hpp"
#include "global.hpp"
#include "AES.hpp"
#include "TLS_enums.hpp"

#include <cstdlib>
#include <array>
#include <vector>
#include <cstring>
#include <algorithm>
#include <arpa/inet.h>
#include <sys/types.h>



constexpr int AES_BLOCK_SIZE = 16;



namespace fbw::aes {


static inline uint32_t AES_GET_BE32(const uint8_t *a) {
    return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline void AES_PUT_BE32(uint8_t *a, uint32_t val) {
    a[0] = (val >> 24) & 0xff;
    a[1] = (val >> 16) & 0xff;
    a[2] = (val >> 8) & 0xff;
    a[3] = val & 0xff;
}

static inline void AES_PUT_BE64(uint8_t *a, uint64_t val)
{
    a[0] = val >> 56;
    a[1] = val >> 48;
    a[2] = val >> 40;
    a[3] = val >> 32;
    a[4] = val >> 24;
    a[5] = val >> 16;
    a[6] = val >> 8;
    a[7] = val & 0xff;
}

static void inc32(aes_block& block) {
    uint32_t val;
    val = AES_GET_BE32(&block[block.size() - 4]);
    val++;
    AES_PUT_BE32(&block[block.size() - 4], val);
    file_assert(val != uint32_t(-1), "2^64 increments should be infeasible");
}


static void xor_block(uint8_t *dst, const uint8_t *src) {
    for(int i = 0; i < 16; i ++) {
        *dst++ ^= *src++;
    }
}


static void shift_right_block(uint8_t *v)
{
    uint32_t val;

    val = AES_GET_BE32(v + 12);
    val >>= 1;
    if (v[11] & 0x01)
        val |= 0x80000000;
    AES_PUT_BE32(v + 12, val);

    val = AES_GET_BE32(v + 8);
    val >>= 1;
    if (v[7] & 0x01)
        val |= 0x80000000;
    AES_PUT_BE32(v + 8, val);

    val = AES_GET_BE32(v + 4);
    val >>= 1;
    if (v[3] & 0x01)
        val |= 0x80000000;
    AES_PUT_BE32(v + 4, val);

    val = AES_GET_BE32(v);
    val >>= 1;
    AES_PUT_BE32(v, val);
}



static void gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *z)
{
    uint8_t v[16];
    int i, j;

    memset(z, 0, 16);
    memcpy(v, y, 16);

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            if (x[i] & 1 << (7 - j)) {

                xor_block(z, v);
            } else {

            }

            if (v[15] & 0x01) {
                shift_right_block(v);

                v[0] ^= 0xe1;
            } else {
                shift_right_block(v);
            }
        }
    }
}




// same as original
static void ghash(const uint8_t *h, const uint8_t *x, size_t xlen, uint8_t *y) {
    const uint8_t *xpos = x;
    uint8_t tmp[16];

    size_t m = xlen / 16;

    for (size_t i = 0; i < m; i++) {
        xor_block(y, xpos);
        xpos += 16;

        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }

    if (x + xlen > xpos) {

        size_t last = x + xlen - xpos;
        memcpy(tmp, xpos, last);
        memset(tmp + last, 0, sizeof(tmp) - last);


        xor_block(y, tmp);

        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }


}


static void aes_gctr(roundkey aesk, aes_block cb, const uint8_t *x, size_t xlen, uint8_t *y)
{
    size_t last;
    
    
    //const uint8_t *xpos = x;
    //uint8_t *ypos = y;

    if (xlen == 0)
        return;

    

    auto roundedx = (xlen &~15u);
    
    

    for (size_t i = 0; i < roundedx; i += AES_BLOCK_SIZE) {
        
        
        auto yy = aes_encrypt(cb, aesk);
        

        std::transform(yy.begin(), yy.end(), &x[i], yy.begin(), std::bit_xor<uint8_t>());
        memcpy(&y[i], &yy[0], AES_BLOCK_SIZE);
        

        inc32(cb);
    }

    last = xlen - roundedx;
    if (last) {

        auto tmp = aes_encrypt(cb, aesk);
        for (size_t i = 0; i < last; i++)
            y[i+roundedx] = x[i+roundedx] ^ tmp[i];
    }
}




static aes_block aes_gcm_prepare_j0(const ustring& iv, const aes_block& H)
{
    uint8_t len_buf[16];
    
    aes_block J0 {};

    if (iv.size() == 12) {
        // Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96]
        std::copy(iv.begin(), iv.end(), J0.begin());
        J0[J0.size() - 1] = 0x01;
    } else {
        
        ghash(H.data(), iv.data(), iv.size(), J0.data());
        AES_PUT_BE64(len_buf, 0);
        AES_PUT_BE64(len_buf + 8, iv.size() * 8);
        ghash(H.data(), len_buf, sizeof(len_buf), J0.data());
    }
    return J0;
}


static void aes_gcm_gctr(roundkey aesk, const aes_block& J0, const uint8_t *in, size_t len,
                         uint8_t *out)
{
    if (len == 0) {
        return;
    }
    auto J0inc = J0;
    inc32(J0inc);
    aes_gctr(aesk, J0inc, in, len, out);
}


static ustring aes_gcm_ghash(const aes_block& H, const ustring& aad,
              const uint8_t *crypt, size_t crypt_len) {
    uint8_t len_buf[16];
    
    ustring S {};
    S.resize(16);
    ghash(H.data(), aad.data(), aad.size(), S.data());
    ghash(H.data(), crypt, crypt_len, S.data());
    AES_PUT_BE64(len_buf, aad.size() * 8);
    AES_PUT_BE64(len_buf + 8, crypt_len * 8);
    ghash(H.data(), len_buf, sizeof(len_buf), S.data());
    return S;
}


// aes_gcm_ae - GCM-AE_K(IV, P, A)

std::pair<ustring,ustring> aes_gcm_ae(const roundkey& rk, const ustring& iv,
           const ustring& plain,
           const ustring& aad) {
    aes_block H {};
    ustring tag;

    H = aes_encrypt(H, rk);

    aes_block J0 = aes_gcm_prepare_j0(iv, H);
    ustring crypt;
    crypt.resize(plain.size());
    aes_gcm_gctr(rk, J0, plain.data(), plain.size(), crypt.data());
    
    
    auto S = aes_gcm_ghash(H, aad, crypt.data(), crypt.size());
    
    
    tag.resize(S.size());
    aes_gctr(rk, J0, S.data(), S.size(), tag.data());
    
    
    
    return {crypt, tag};
}



// aes_gcm_ad - GCM-AD_K(IV, C, A, T)

ustring aes_gcm_ad(roundkey rk, ustring iv,
           const ustring& crypt,
                   const ustring& aad, const ustring& tag) {
    
    aes_block H {};
    aes_block T {};
    ustring plain;
    
    H = aes_encrypt(H, rk);
    aes_block J0 = aes_gcm_prepare_j0(iv, H);
    plain.resize(crypt.size());
    aes_gcm_gctr(rk, J0, crypt.data(), crypt.size(), plain.data());
    ustring S = aes_gcm_ghash(H, aad, crypt.data(), crypt.size());
    aes_gctr(rk, J0, S.data(), S.size(), &T[0]);
    if(!std::equal(tag.begin(), tag.end(), T.begin())) {
        throw ssl_error("bad tag", AlertLevel::fatal, AlertDescription::bad_record_mac);
    }

    return plain;
}


ustring aes_gmac(roundkey key, const ustring& iv,
         const ustring& aad) {
    file_assert(false, "function should be inaccessible");
    auto [_, tag] = aes_gcm_ae(key, iv, {}, aad);
    return tag;
}




void AES_128_GCM_SHA256::set_key_material(ustring material) {

    std::vector<uint8_t> client_write_key;
    client_write_key.resize(16);
    std::vector<uint8_t> server_write_key;
    server_write_key.resize(16);
    
    client_implicit_write_IV.resize(4);
    server_implicit_write_IV.resize(4);
    
    auto it = material.begin();
    std::copy_n(it, client_write_key.size(), client_write_key.begin());
    it += client_write_key.size();
    std::copy_n(it, server_write_key.size(), server_write_key.begin());
    it += server_write_key.size();
    std::copy_n(it, client_implicit_write_IV.size(), client_implicit_write_IV.begin());
    it += client_implicit_write_IV.size();
    std::copy_n(it, server_implicit_write_IV.size(), server_implicit_write_IV.begin());
    it += server_implicit_write_IV.size();
    
    
    client_write_round_keys = aes_key_schedule(client_write_key);
    server_write_round_keys = aes_key_schedule(server_write_key);

}


tls_record AES_128_GCM_SHA256::encrypt(tls_record record) {

    
    ustring sequence_no;
    sequence_no.resize(8);
    
    write_int(seqno_server, sequence_no.data(), 8);
    seqno_server++;

    
    uint16_t msglen = htons(record.m_contents.size());

    
    ustring additional_data = sequence_no;
    
    additional_data.append({record.get_type(), record.get_major_version(), record.get_minor_version()});
    
    
    additional_data.resize(13);
    std::memcpy(&additional_data[11], &msglen, 2);
    
    ustring iv = server_implicit_write_IV + sequence_no;

    
    auto [ciphertext, auth_tag] = aes_gcm_ae(server_write_round_keys, iv, record.m_contents, additional_data);
    
    file_assert(auth_tag.size() == 16, "no auth tag");
    file_assert(sequence_no.size() == 8, "no seq no");
    
    record.m_contents = sequence_no + ciphertext + auth_tag;
    return record;
}

tls_record AES_128_GCM_SHA256::decrypt(tls_record record) {
    
    if(record.m_contents.size() < 24) {
        throw ssl_error("short record", AlertLevel::fatal, AlertDescription::decrypt_error);
    }
    
    ustring sequence;
    sequence.resize(8);
    write_int(seqno_client, sequence.data(), 8);
    seqno_client++;

    ustring explicit_IV;
    explicit_IV.append({record.m_contents.begin(), record.m_contents.begin()+8});
    ustring ciphertext;
    ciphertext.append({record.m_contents.begin()+8, record.m_contents.end()-16});
    ustring auth_tag;
    auth_tag.append({record.m_contents.end()-16, record.m_contents.end()});
    
    file_assert(auth_tag.size() == 16, "bad auth tag");
    file_assert(explicit_IV.size() == 8,  "bad explicit_IV");
    
    ustring additional_data;
    additional_data.append(sequence);
    additional_data.append({record.get_type(), record.get_major_version(), record.get_minor_version()});
    additional_data.resize(13);
    uint16_t msglen = htons(record.m_contents.size() - auth_tag.size() - explicit_IV.size());
    std::memcpy(&additional_data[11], &msglen, 2);

    auto iv = client_implicit_write_IV + explicit_IV;
    
    ustring plain = aes_gcm_ad(client_write_round_keys, iv, ciphertext, additional_data, auth_tag);
    record.m_contents = plain;
     
    return record;
}



void AES_128_GCM_SHA256::test() {
    
    
    std::vector<uint8_t> KEY = {0xAD, 0x7A, 0x2B, 0xD0, 0x3E, 0xAC, 0x83, 0x5A, 0x6F, 0x62, 0x0F, 0xDC, 0xB5, 0x06, 0xB3, 0x45 };
    auto aesk = aes_key_schedule(KEY);
    
    // plaintext:
    ustring plain = { 0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                      0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x00, 0x02 };
    
    // Additional:
    ustring additional { 0xD6, 0x09, 0xB1, 0xF0, 0x56, 0x63, 0x7A, 0x0D, 0x46, 0xDF, 0x99, 0x8D, 0x88, 0xE5, 0x2E, 0x00,
        0xB2, 0xC2, 0x84, 0x65, 0x12, 0x15, 0x35, 0x24, 0xC0, 0x89, 0x5E, 0x81 };
    
    ustring IV { 0x12, 0x15, 0x35, 0x24, 0xC0, 0x89, 0x5E, 0x81, 0xB2, 0xC2, 0x84, 0x65 };
    
    // produces:
    // ciphertext:
    ustring ciphertext { 0x70, 0x1A, 0xFA, 0x1C, 0xC0, 0x39, 0xC0, 0xD7, 0x65, 0x12, 0x8A, 0x66, 0x5D, 0xAB, 0x69, 0x24,
            0x38, 0x99, 0xBF, 0x73, 0x18, 0xCC, 0xDC, 0x81, 0xC9, 0x93, 0x1D, 0xA1, 0x7F, 0xBE, 0x8E, 0xDD,
            0x7D, 0x17, 0xCB, 0x8B, 0x4C, 0x26, 0xFC, 0x81, 0xE3, 0x28, 0x4F, 0x2B, 0x7F, 0xBA, 0x71, 0x3D };
    
    //ustring plain2 = aes_gcm_ad(aesk, IV, ciphertext, additional, taga);
    

    auto [cipher, tag] = aes_gcm_ae(aesk, IV, plain, additional);
    

    ustring plain_new = aes_gcm_ad(aesk, IV, ciphertext, additional, tag);
    
    
}




} // namespace fbw
