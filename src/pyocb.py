#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# pyocb.py
# --------
# Functional model of OCB mode. The model tries fo follow the
# description in RFC7253. The big difference is that support for
# 102 bit keys are not included.
#
#
# Copyright (c) 2016 Assured AB
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
from pyaes import AES


#-------------------------------------------------------------------
# OCB()
#-------------------------------------------------------------------
class OCB():
    BLOCKSIZE = 128
    LCACHE = 1

    #---------------------------------------------------------------
    # __init__()
    #---------------------------------------------------------------
    def __init__(self, keylen=128, taglen=128, verbose = False):
        self.aes = AES()
        self.verbose = verbose
        self.L = [[0]] * self.LCACHE

        if keylen not in [128, 256]:
            print("Unsupported key length: %d bits" % keylen)
            return
        self.keylen = keylen

        if taglen not in [64, 96, 128]:
            print("Unsupported tag length: %d bits" % taglen)
            return
        self.taglen = taglen


    #---------------------------------------------------------------
    # hash()
    #
    # Hash associated data before encipher. Returns the
    # 128 bit all zero vector when there is no associated data.
    #---------------------------------------------------------------
    def hash(self, key, associated_data):
        L_star = self.aes.encipher(key, [0] * 128)
        self._init_L(L_star)

        m = int(len(associated_data) / self.BLOCKSIZE)
        hsum = [0] * 128
        offset = [0] * 128

        for i in range((m - 1)):
            offset = offset ^ self._get_L(i)
            ai = associated_data[(i * self.blocksize) : ((i + 1) * self.BLOCKSIZE)]
            hsum = hsum ^ self.aes.encipher(key, (offset ^ ai))


    #---------------------------------------------------------------
    # encrypt()
    #---------------------------------------------------------------
    def encrypt(self, key, nonce, associated_data, plaintext):
        hsum = self.hash(self, key, associated_data)


    #---------------------------------------------------------------
    # decrypt()
    #---------------------------------------------------------------
    def decrypt(self, key, nonce, associated_data, ciphertext):
        return False


    def _calc_L_i(self, block, i):
        pass


    def _double(self, prev_l):
        return prev_l << 1


    def _init_L(self, star):
        l = self._double(self._double(star))
        for i in range(self.lcache):
            self.L[i] = l
            l = self._double(l)


    def _get_L(i):
        # We need to find number of trailing zeros here an use as index.
        if i <= self.lcache:
            return self.L[i]
        else:
            j = i - 1
            l = self.L[(self.lcache - 1)]


#-------------------------------------------------------------------
# test_ocb()
#
# Run tests using test vectors from RFC7253.
# https://tools.ietf.org/html/rfc7253
#-------------------------------------------------------------------
def test_ocb():
    print("Testing the OCB implementation")
    print("------------------------------\n")

    my_ocb = OCB()


#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__":
    # Run the main function.
    sys.exit(test_ocb())

#=======================================================================
# EOF pyocb.py
#=======================================================================
