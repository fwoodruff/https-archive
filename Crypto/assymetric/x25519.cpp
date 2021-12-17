//
//  curve25519.cpp
//  curve25519
//
//  Created by Frederick Benjamin Woodruff on 08/08/2021.
//


#include "bignum.hpp"
#include "x25519.hpp"

#include <cassert>
#include <array>
#include <string>
#include <sstream>
#include <iostream>
#include <climits>



namespace fbw::curve25519 {





using namespace std::literals;

struct point256 {
    ct_u256 xcoord;
    ct_u256 affine;
    // x coordinate = xcoord * affine^-1
    // y coordinate is implicit
};

// We consider the group of points on the curve
// y^2 = x^3 + A x^2 + x mod P
// A = 486662
// P = 2^255 - 19
// with integer coordinates modulo P (and points infinitesimally close).
// For the group operation P + Q -> R, find the third point on the line through P + Q, at coordinates (a,b), then R = (a,P-b)

// R = 2^256
// B = 2^64

// P
constexpr ct_u256 Prime  = ("0x1"_xl << 255) - "0x13"_xl;
constexpr ct_u256 Prime2 = Prime - "0x2"_xl;

// M such that ((R-M)*P)%P = 0, M < P
constexpr ct_u256 Magic = "0x2f286bca1af286bca1af286bca1af286bca1af286bca1af286bca1af286bca1b"_xl;
// R mod P
constexpr ct_u256 R_P = "0x26"_xl;

// R^2 mod P
constexpr ct_u256 RR_P = "0x5a4"_xl;

// A*R mod P
constexpr ct_u256 AR_P= "0x11a2ee4"_xl;

// G
constexpr point256 Base {"0x9"_xl,"0x1"_xl};

// computes a such that aR = a * R mod N
constexpr ct_u256 REDC(ct_u512 aR) noexcept {
    using radix = ct_u256::radix;
    using radix2 = ct_u256::radix2;
    ct_u256 a;
    for(size_t i = 0; i < a.v.size(); i++) {
        radix2 carry = 0;
        radix2 congruent_multiplier = static_cast<radix>(aR.v[i]*Magic.v[0]);
        
        for(size_t j = 0; j < a.v.size(); j++) {
            radix2 x = static_cast<radix2>(aR.v[i+j]) + congruent_multiplier * static_cast<radix2>(Prime.v[j]) + carry;
            aR.v[i+j] = static_cast<radix>(x);
            carry = x >> ct_u256::RADIXBITS;
        }
        for(size_t j = a.v.size(); j < aR.v.size() - i; j++){
            radix2 x = static_cast<radix2>(aR.v[i+j]) + carry;
            aR.v[i+j] = static_cast<radix>(x);
            carry = x >> ct_u256::RADIXBITS;
        }
    }
    for(size_t i = 0; i < Prime.v.size(); i++) {
        a.v[i] = aR.v[i + Prime.v.size()];
    }
    if(a>Prime) {
        return a - Prime;
    } else {
        return a;
    }
}



// computes a' such that a * a' = 1 mod P
constexpr ct_u256 modular_inverse(const ct_u256& a) {
    auto ladder = R_P;
    auto aR = REDC(a*RR_P);
    for(int i = sizeof(ct_u256)*CHAR_BIT-1; i >=0; i--) {
        auto prime_shift = Prime2 >> i;
        if(prime_shift == "0x0"_xl) {
            continue;
        }
        auto reduced = REDC(ladder*ladder);
        auto next = REDC(aR*reduced);
        if((prime_shift&"0x1"_xl) != "0x0"_xl) {
            ladder = next;
        } else {
            ladder = reduced;
        }
    }
    return REDC(ct_u512(ladder));
}





// computes lhs + rhs mod P
constexpr ct_u256 modulo_add(const ct_u256& lhs, const ct_u256& rhs) {
    assert(lhs < Prime and rhs < Prime);
    ct_u256 summand = lhs + rhs;
    return summand >= Prime ? summand - Prime : summand;
}

// computes lhs - rhs mod P
constexpr ct_u256 modulo_sub(const ct_u256& lhs, const ct_u256& rhs) {
    assert(lhs < (Prime+Prime) and rhs < Prime);
    if(lhs>=rhs) {
        return lhs-rhs;
    } else {
        
        return (Prime+lhs) - rhs;
    }
}


// finds point R, on the line through P and Q
// The y coordinate is inferred from the base point.
constexpr point256 point_add(const point256& P, const point256& Q, const point256& base) {
    ct_u256 dif1 = modulo_sub(REDC(Q.xcoord * P.xcoord), REDC(Q.affine * P.affine));
    ct_u256 dif2 = modulo_sub(REDC(Q.xcoord * P.affine), REDC(Q.affine * P.xcoord));
    ct_u256 aa = modulo_add(dif1, dif1);
    ct_u256 bb = modulo_add(dif2, dif2);
    return {REDC(REDC(aa * aa) * base.affine), REDC(REDC(bb * bb) * base.xcoord)};
}


// finds point R on the line tangent to point P on the curve
constexpr point256 point_double(const point256& P) {
    ct_u256 point_xz = REDC(P.xcoord * P.affine);
    ct_u256 point_xx = REDC(P.xcoord * P.xcoord);
    ct_u256 point_zz = REDC(P.affine * P.affine);
    ct_u256 Azzn = modulo_add(point_xx, REDC(AR_P *  point_xz));
    ct_u256 point_xxzz = modulo_sub(point_xx, point_zz);
    point_xz = modulo_add(point_xz, point_xz);
    point_xz = modulo_add(point_xz, point_xz);
    Azzn = modulo_add(Azzn, point_zz);
    return { REDC(point_xxzz * point_xxzz), REDC(point_xz * Azzn) };
}

// computes P + P + ... + P (N times) and returns the x coordinate.
// x_coord is the x coordinate of P, and N is some secret number.
// note that we assume that the y coordinate of P is the same as G's.
ct_u256 point_multiply(const ct_u256& secret, const ct_u256& x_coord) { // is this using the wrong endianness??
    const point256 base_point = {x_coord,"0x1"_xl};
    auto current_point = base_point;
    auto current_double = point_double(base_point);
    
    int maxbit = sizeof(ct_u256)*CHAR_BIT-1;
    for(int i = maxbit; i>=0; i--) {
        auto shift_secret = secret >> i;
        if(shift_secret <= "0x1"_xl) {
            continue;
        }
        auto third_point = point_add(current_point, current_double, base_point);
        auto tangent_intersect = point_double(current_point);
        auto next_intersect = point_double(current_double);

        if((shift_secret & "0x1"_xl) == "0x1"_xl){
            current_point = third_point;
            current_double = next_intersect;
        } else {
            current_point = tangent_intersect;
            current_double = third_point;
        }
    }
    return (current_point.xcoord * modular_inverse(current_point.affine) )% Prime;
}

// takes any_value and flips a few bits to ensure that the point is on the prime order curve.
// Without this, someone could pick a point for which 9*P = P, and quickly decipher a private key.
constexpr ct_u256 clamp(ct_u256 any_value) {
    any_value &= ~"0x7"_xl ;
    any_value &= ~("0x1"_xl << 255);
    any_value |= "0x1"_xl << 254;
    return any_value;
}

// point multiplies serial_point by secret.
// only takes the x coordinate of the point as input to avoid an invalid curve attack
std::array<unsigned char,32> multiply(const std::array<unsigned char,32>& secret,
                                                          const std::array<unsigned char,32>& serial_point) {
    auto clamped_secret = clamp(ct_u256(secret));
    auto curve_point_x = ct_u256(serial_point);
    auto out_point = point_multiply(clamped_secret, curve_point_x);
    return out_point.serialise();
}

// point multiplies the base point by secret.
std::array<unsigned char,32> base_multiply(const std::array<unsigned char,32>& secret) {
    auto clamped_secret = clamp(ct_u256(secret));
    auto output_point = point_multiply(clamped_secret, Base.xcoord);
    return output_point.serialise();
}

/*
std::array<unsigned char, 64>
EdDSA(const std::array<unsigned char,32>& ran,
      const std::array<unsigned char,32>& dig,
      const std::array<unsigned char,32>& priv) {
    
    ct_u256 random256 = ct_u256(ran);
    ct_u256 digest256 = ct_u256(dig);
    ct_u256 privkey256 = ct_u256(priv);
    random256 = clamp(random256);
    privkey256 = clamp(privkey256);
    
    auto k = point_multiply(random256, Base.xcoord);
    auto kp = modular_inverse(k);
    auto x = (kp * (ct_u512(digest256) + random256 * privkey256)) % Prime;
    auto xs = x.serialise();
    auto ks = k.serialise();
    std::array<unsigned char, 64> out;
    std::copy(ks.begin(), ks.end(), out.begin());
    std::copy(xs.begin(), xs.end(), &out[32]);
    return out;
}
 */

} // namespace fbw::curve25519


