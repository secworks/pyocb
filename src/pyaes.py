#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# pyaes.py
# --------
# A simple class that implements the AES cipher. Used by the
# OCB mode model. This implementation is a class version of
# the code used in the AES HW core functional model.
#
#
# Copyright (c) 2016 Secworks Sweden AB
# Author: Joachim Strömbergson
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#=======================================================================

#-------------------------------------------------------------------
# Python module imports.
#-------------------------------------------------------------------
import sys


#-------------------------------------------------------------------
# AES()
#
# A simple class that implements the AES block cipher.
# (See NIST FIPS-197)
#-------------------------------------------------------------------
class AES():
    AES_128_ROUNDS = 10
    AES_256_ROUNDS = 14

    sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
            0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
            0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
            0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
            0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
            0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
            0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
            0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
            0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
            0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
            0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
            0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
            0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
            0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
            0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

    inv_sbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
                0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
                0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
                0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
                0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
                0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
                0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
                0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
                0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
                0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
                0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
                0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
                0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
                0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
                0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
                0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
                0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]


    #---------------------------------------------------------------
    # __init__()
    #---------------------------------------------------------------
    def __init__(self, verbose = False):
        self.verbose = verbose


    #---------------------------------------------------------------
    # encipher()
    # Given a 128 or 256 bit key will perform AES encipher on
    # the given 128 bit block.
    #---------------------------------------------------------------
    def encipher(self, key, block):
        if self.verbose:
            print("AES encipher operation.")
        tmp_block = block[:]
        (round_keys, num_rounds) = self._expand_key(key)

        # Init round
        if self.verbose:
            print("Initial AddRoundKeys round.")
        tmp_block4 = self._addroundkey(round_keys[0], block)

        # Main rounds
        for i in range(1 , (num_rounds)):
            if self.verbose:
                print("Round %02d" % i)
            tmp_block1 = self._subbytes(tmp_block4)
            tmp_block2 = self._shiftrows(tmp_block1)
            tmp_block3 = self._mixcolumns(tmp_block2)
            tmp_block4 = self._addroundkey(round_keys[i], tmp_block3)

        # Final round
        if self.verbose:
            print("  Final round.")
        tmp_block1 = self._subbytes(tmp_block4)
        tmp_block2 = self._shiftrows(tmp_block1)
        tmp_block3 = self._addroundkey(round_keys[num_rounds], tmp_block2)
        return tmp_block3


    #---------------------------------------------------------------
    # decipher()
    #---------------------------------------------------------------
    def decipher(self, key, block):
        if self.verbose:
            print("AES decipher operation.")
        self.tmp_block = block[:]
        (self.round_keys, self.num_rounds) = self._expand_key(key)

        # Initial round
        if self.verbose:
            print("Initial, partial round.")
        self.tmp_block1 = self._addroundkey(self.round_keys[len(self.round_keys) - 1],
                                                self.tmp_block)
        self.tmp_block2 = self._inv_shiftrows(self.tmp_block1)
        self.tmp_block4 = self._inv_subbytes(self.tmp_block2)

        # Main rounds
        for i in range(1 , (num_rounds)):
            if self.verbose:
                print("Round %02d" % self.i)
            self.tmp_block1 = self._addroundkey(self.round_keys[(len(self.round_keys) - i - 1)],
                                                    self.tmp_block4)
            self.tmp_block2 = self._inv_mixcolumns(self.tmp_block1)
            self.tmp_block3 = self._inv_shiftrows(self.tmp_block2)
            self.tmp_block4 = self._inv_subbytes(self.tmp_block3)

        # Final round
        print("Final AddRoundKeys round.")
        self.res_block = self._addroundkey(self.round_keys[0], self.tmp_block4)

        return res_block


    #---------------------------------------------------------------
    # self_test()
    #
    # Perform self test of AES functionality using NIST
    # test vectors.
    #---------------------------------------------------------------
    def self_test(self):
        nist_aes128_key = (0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c)
        nist_aes256_key = (0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
                            0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4)
        nist_plaintext0 = (0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a)
        nist_exp128_0 = (0x3ad77bb4, 0x0d7a3660, 0xa89ecaf3, 0x2466ef97)
        nist_exp256_0 = (0xf3eed1bd, 0xb5d2a03c, 0x064b5a7e, 0x3db181f8)

        print("Encipher tests.")
        result = self.encipher(nist_aes128_key, nist_plaintext0)
        if result == nist_exp128_0:
            print("128 bit key mode ok")
        else:
            print("Error, expected: ", nist_exp128_0)
            print("Got:             ", result)

        result = self.encipher(nist_aes256_key, nist_plaintext0)
        if result == nist_exp256_0:
            print("256 bit key mode ok")
        else:
            print("Error, expected: ", nist_exp128_0)
            print("Got:             ", result)
        print("")


    #---------------------------------------------------------------
    # Internal methods.
    #---------------------------------------------------------------
    def _subbytes(self, block):
        (w0, w1, w2, w3) = block
        return (self.__substw(w0), self.__substw(w1), self.__substw(w2), self.__substw(w3))


    def _shiftrows(self, block):
        (w0, w1, w2, w3) = block
        c0 = self.__w2b(w0)
        c1 = self.__w2b(w1)
        c2 = self.__w2b(w2)
        c3 = self.__w2b(w3)
        ws0 = self.__b2w(c0[0], c1[1],  c2[2],  c3[3])
        ws1 = self.__b2w(c1[0], c2[1],  c3[2],  c0[3])
        ws2 = self.__b2w(c2[0], c3[1],  c0[2],  c1[3])
        ws3 = self.__b2w(c3[0], c0[1],  c1[2],  c2[3])
        return (ws0, ws1, ws2, ws3)


    def _mixcolumns(self, block):
        (c0, c1, c2, c3) = block
        return (self.__mixw(c0), self.__mixw(c1), self.__mixw(c2), self.__mixw(c3))


    def _addroundkey(self, round_key, block):
        (w0, w1, w2, w3) = block
        (k0, k1, k2, k3) = round_key
        return (w0 ^ k0, w1 ^ k1, w2 ^ k2, w3 ^ k3)


    def _expand_key(self, key):
        if len(key) == 4:
            round_keys = self.__key_gen128(key)
            num_rounds = self.AES_128_ROUNDS
        else:
            round_keys = self.__key_gen256(key)
            num_rounds = self.AES_256_ROUNDS
        return (round_keys, num_rounds)


    def __key_gen128(self, key):
        round_keys = []
        round_keys.append(key)
        for i in range(10):
            round_keys.append(self.__next_128bit_key(round_keys[i], self.__get_rcon(i + 1)))
        return round_keys


    def __next_128bit_key(self, prev_key, rcon):
        (w0, w1, w2, w3) = prev_key
        rol = self.__rolx(w3, 8)
        subst = self.__substw(rol)
        t = subst ^ (rcon << 24)
        k0 = w0 ^ t
        k1 = w1 ^ w0 ^ t
        k2 = w2 ^ w1 ^ w0 ^ t
        k3 = w3 ^ w2 ^ w1 ^ w0 ^ t
        return (k0, k1, k2, k3)


    def __key_gen256(self, key):
        round_keys = []
        (k0, k1, k2, k3, k4, k5, k6, k7) = key
        round_keys.append((k0, k1, k2, k3))
        round_keys.append((k4, k5, k6, k7))

        j = 1
        for i in range(0, (self.AES_256_ROUNDS - 2), 2):
            k = self.__next_256it_key_a(round_keys[i], round_keys[i + 1], self.__get_rcon(j))
            round_keys.append(k)
            k = self.__next_256it_key_b(round_keys[i + 1], round_keys[i + 2])
            round_keys.append(k)
            j += 1

        # One final key needs to be generated.
        k = self.__next_256it_key_a(round_keys[12], round_keys[13], self.__get_rcon(7))
        round_keys.append(k)
        return round_keys


    def __next_256it_key_a(self, key0, key1, rcon):
        (w0, w1, w2, w3) = key0
        (w4, w5, w6, w7) = key1

        sw = self.__substw(self.__rolx(w7, 8))
        rw = (rcon << 24)
        t = sw ^ rw

        k0 = w0 ^ t
        k1 = w1 ^ w0 ^ t
        k2 = w2 ^ w1 ^ w0 ^ t
        k3 = w3 ^ w2 ^ w1 ^ w0 ^ t
        return (k0, k1, k2, k3)


    def __next_256it_key_b(self, key0, key1):
        (w0, w1, w2, w3) = key0
        (w4, w5, w6, w7) = key1
        t = self.__substw(w7)
        k0 = w0 ^ t
        k1 = w1 ^ w0 ^ t
        k2 = w2 ^ w1 ^ w0 ^ t
        k3 = w3 ^ w2 ^ w1 ^ w0 ^ t
        return (k0, k1, k2, k3)


    def __get_rcon(self, round):
        rcon = 0x8d
        for i in range(0, round):
            rcon = ((rcon << 1) ^ (0x11b & - (rcon >> 7))) & 0xff
        return rcon


    def __rolx(self, w, x):
        return ((w << x) | (w >> (32 - x))) & 0xffffffff


    def __substw(self, w):
        (b0, b1, b2, b3) = self.__w2b(w)
        return self.__b2w(self.sbox[b0], self.sbox[b1], self.sbox[b2], self.sbox[b3])


    def __mixw(self, w):
        (b0, b1, b2, b3) = self.__w2b(w)
        mb0 = self.__gm2(b0) ^ self.__gm3(b1) ^ b2      ^ b3
        mb1 = b0      ^ self.__gm2(b1) ^ self.__gm3(b2) ^ b3
        mb2 = b0      ^ b1      ^ self.__gm2(b2) ^ self.__gm3(b3)
        mb3 = self.__gm3(b0) ^ b1      ^ b2      ^ self.__gm2(b3)
        return self.__b2w(mb0, mb1, mb2, mb3)


    def __b2w(self, b0, b1, b2, b3):
        return (b0 << 24) + (b1 << 16) + (b2 << 8) + b3


    def __w2b(self, w):
        return (w >> 24, w >> 16 & 0xff, w >> 8 & 0xff, w & 0xff)


    def __gm2(self, b):
        return ((b << 1) ^ (0x1b & ((b >> 7) * 0xff))) & 0xff


    def __gm3(self, b):
        return self.__gm2(b) ^ b


#-------------------------------------------------------------------
# main()
#-------------------------------------------------------------------
def main():
    my_aes = AES()
    my_aes.self_test()


#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__":
    # Run the main function.
    sys.exit(main())

#=======================================================================
# EOF pyaes.py
#=======================================================================
