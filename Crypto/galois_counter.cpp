//
//  galois_counter.cpp
//  https_server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#include <cstdlib>
#include "galois_counter.hpp"
#include "AES.hpp"
#include "global.hpp"
#include <array>
#include <vector>

typedef unsigned char       aes_uchar;
typedef unsigned short      aes_ushort;
typedef unsigned int        aes_uint;
typedef unsigned long long  aes_ulong;
typedef signed char         aes_char;
typedef signed short        aes_short;
typedef signed int          aes_int;
typedef signed long long    aes_long;
#define AES_BLOCK_SIZE 16
enum {
    MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR
};



namespace fbw::aes {


/*
 * Galois/Counter Mode (GCM) and GMAC with AES
 *
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */










static inline aes_uint AES_GET_BE32(const aes_uchar *a)
{
    return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline void AES_PUT_BE32(aes_uchar *a, aes_uint val)
{
    a[0] = (val >> 24) & 0xff;
    a[1] = (val >> 16) & 0xff;
    a[2] = (val >> 8) & 0xff;
    a[3] = val & 0xff;
}




static inline void AES_PUT_BE64(aes_uchar *a, aes_ulong val)
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
    aes_uint val;
    
    val = AES_GET_BE32(&block[AES_BLOCK_SIZE - 4]);
    val++;
    AES_PUT_BE32(&block[AES_BLOCK_SIZE - 4], val);
    assert (val != aes_uint(-1));
}


static void xor_block(aes_uchar *dst, const aes_uchar *src)
{
    aes_uint *d = (aes_uint *) dst;
    aes_uint *s = (aes_uint *) src;
    *d++ ^= *s++;
    *d++ ^= *s++;
    *d++ ^= *s++;
    *d++ ^= *s++;
}


static void shift_right_block(aes_uchar *v)
{
    aes_uint val;

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



static void gf_mult(const aes_uchar *x, const aes_uchar *y, aes_uchar *z)
{
    aes_uchar v[16];
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




static void ghash(const aes_uchar *h, const aes_uchar *x, size_t xlen, aes_uchar *y)
{
    size_t m, i;
    const aes_uchar *xpos = x;
    aes_uchar tmp[16];

    m = xlen / 16;

    for (i = 0; i < m; i++) {
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


static void aes_gctr(roundkey aesk, aes_block cb, const aes_uchar *x, size_t xlen, aes_uchar *y)
{
    size_t i, n, last;
    
    
    const aes_uchar *xpos = x;
    aes_uchar *ypos = y;

    if (xlen == 0)
        return;

    n = xlen / 16;



    for (i = 0; i < n; i++) {
        
        
        auto yy = aes_encrypt(cb, aesk);
        

        std::transform(yy.begin(), yy.end(), xpos, yy.begin(), std::bit_xor<uint8_t>());
        memcpy(ypos, &yy[0], AES_BLOCK_SIZE);
        
        //xor_block(ypos, xpos);
        xpos += AES_BLOCK_SIZE;
        ypos += AES_BLOCK_SIZE;
        inc32(cb);
    }

    last = x + xlen - xpos;
    if (last) {

        auto tmp = aes_encrypt(cb, aesk);
        for (i = 0; i < last; i++)
            *ypos++ = *xpos++ ^ tmp[i];
    }
}




static aes_block aes_gcm_prepare_j0(const ustring& iv, const aes_block& H)
{
    aes_uchar len_buf[16];
    
    aes_block J0 {};

    if (iv.size() == 12) {
        // Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96]
        std::copy(iv.begin(), iv.end(), J0.begin());
        J0[AES_BLOCK_SIZE - 1] = 0x01;
    } else {

        ghash(H.data(), iv.data(), iv.size(), J0.data());
        AES_PUT_BE64(len_buf, 0);
        AES_PUT_BE64(len_buf + 8, iv.size() * 8);
        ghash(H.data(), len_buf, sizeof(len_buf), J0.data());
    }
    return J0;
}


static void aes_gcm_gctr(roundkey aesk, aes_block& J0, const aes_uchar *in, size_t len,
             aes_uchar *out)
{
    if (len == 0)
        return;
    inc32(J0);
    aes_gctr(aesk, J0, in, len, out);
}


static ustring aes_gcm_ghash(const aes_block& H, const ustring& aad,
              const aes_uchar *crypt, size_t crypt_len)
{
    aes_uchar len_buf[16];


    
    ustring S {};
    S.resize(16);
    ghash(H.data(), aad.data(), aad.size(), S.data());
    ghash(H.data(), crypt, crypt_len, S.data());
    AES_PUT_BE64(len_buf, aad.size() * 8);
    AES_PUT_BE64(len_buf + 8, crypt_len * 8);
    ghash(H.data(), len_buf, sizeof(len_buf), S.data());
    return S;
    //aes_hexdump_key(MSG_EXCESSIVE, "S = GHASH_H(...)", S, 16);
}


// aes_gcm_ae - GCM-AE_K(IV, P, A)
static ustring DUMMY_TAG;
ustring aes_gcm_ae(const roundkey& rk, const ustring& iv,
           const ustring& plain,
           const ustring& aad, ustring& tag = DUMMY_TAG) {
    aes_block H {};

    H = aes_encrypt(H, rk);
    aes_block J0 = aes_gcm_prepare_j0(iv, H);
    ustring crypt;
    crypt.resize(plain.size());
    aes_gcm_gctr(rk, J0, plain.data(), plain.size(), crypt.data());
    auto S = aes_gcm_ghash(H, aad, crypt.data(), crypt.size());
    if(&tag != &DUMMY_TAG) {
        aes_gctr(rk, J0, S.data(), S.size(), tag.data());
    }
    return crypt;
}



// aes_gcm_ad - GCM-AD_K(IV, C, A, T)

ustring aes_gcm_ad(roundkey rk, ustring iv,
           const ustring& crypt,
                   const ustring& aad, const ustring& tag = {})
{
    
    
    aes_block H;
    
    aes_uchar T[16];
    ustring plain;
    
    H = aes_encrypt(H, rk);



    auto J0 = aes_gcm_prepare_j0(iv, H);

    // P = GCTR_K(inc_32(J_0), C)
    plain.resize(crypt.size());
    
    aes_gcm_gctr(rk, J0, crypt.data(), crypt.size(), plain.data());

    ustring S = aes_gcm_ghash(H, aad, crypt.data(), crypt.size());
    

    // T' = MSB_t(GCTR_K(J_0, S))
    //aes_gctr(aes, J0, S, sizeof(S), T);
    //aes_gctr(rk, J0, S, sizeof(S), T);
    
    if(!tag.empty()) {
        aes_gctr(rk, J0, S.data(), S.size(), T);
        if (memcmp(tag.data(), T, 16) != 0) {
            throw std::logic_error("bad tag");
        }
    }
    
    return plain;
}


void aes_gmac(roundkey key, const ustring& iv,
         const ustring& aad, ustring& tag) {
    assert(false);
    aes_gcm_ae(key, iv, {}, aad, tag);
}




void AES_128_GCM_SHA256::set_key_material(ustring material) {
    /*
     client_write_MAC_key[SecurityParameters.mac_key_length]
           server_write_MAC_key[SecurityParameters.mac_key_length]
           client_write_key[SecurityParameters.enc_key_length]
           server_write_key[SecurityParameters.enc_key_length]
           client_write_IV[SecurityParameters.fixed_iv_length]
           server_write_IV[SecurityParameters.fixed_iv_length]
     */
    std::vector<uint8_t> client_write_key;
    client_write_key.resize(16);
    std::vector<uint8_t> server_write_key;
    server_write_key.resize(16);
    
    client_explicit_write_IV.resize(4);
    server_explicit_write_IV.resize(4);
    
    auto it = material.begin();
    //std::copy(it, it += client_MAC_key.size(), client_MAC_key.begin());
    //std::copy(it, it += client_MAC_key.size(), server_MAC_key.begin());
    std::copy(it, it += client_write_key.size(), client_write_key.begin());
    std::copy(it, it += server_write_key.size(), server_write_key.begin());
    std::copy(it, it += client_explicit_write_IV.size(), client_explicit_write_IV.begin());
    std::copy(it, it += server_explicit_write_IV.size(), server_explicit_write_IV.begin());
    
    client_write_round_keys = aes_key_schedule(client_write_key);
    server_write_round_keys = aes_key_schedule(server_write_key);

}


tls_record AES_128_GCM_SHA256::encrypt(tls_record record) {
    uint64_t sqno = htonll(seqno_server);
    ustring sqnob;
    sqnob.resize(8);
    std::memcpy(&sqnob[0], &sqno, 8);
    uint16_t msglen = htons(record.contents.size());
    
    
    ustring AAD = sqnob;
    AAD.append({record.type, record.major_version, record.minor_version});
    AAD.resize(13);
    std::memcpy(&AAD[11], &msglen, 2);
    
    ustring iv = client_explicit_write_IV + sqnob;
    iv.resize(12);
    
    ustring crypt = aes_gcm_ae(server_write_round_keys, iv, record.contents, AAD);
    
    seqno_server++;
    record.contents = sqnob + crypt + AAD;
    return record;
}

tls_record AES_128_GCM_SHA256::decrypt(tls_record record) {
    if(record.contents.size() < 21) {
        throw ssl_error("short record");
    }
    
    const int AAD_size = 13;
    ustring sqnob;
    sqnob.append(&*record.contents.begin(), &record.contents[8]);
    
    ustring crypt;
    crypt.append(&record.contents[8],record.contents[record.contents.size() - AAD_size]);
    
     ustring AAD;
    AAD.append(&record.contents[record.contents.size() - AAD_size], &*record.contents.end());
    
    auto iv = client_explicit_write_IV + sqnob;
    ustring plain = aes_gcm_ad(client_write_round_keys, iv, crypt, AAD);
    record.contents = plain;
    return record;
}







} // namespace fbw
