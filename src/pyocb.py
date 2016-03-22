#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# pyocb.py
# --------
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
# OCB()
#-------------------------------------------------------------------
class OCB():

    #---------------------------------------------------------------
    # __init__()
    #---------------------------------------------------------------
    def __init__(self, keylen=128, taglen=128, verbose = False):
        self.aes = AES()
        self.verbose = verbose

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
        L_star = aes.encipher(key, my_aes, [0] * 128)


    #---------------------------------------------------------------
    # encrypt()
    #---------------------------------------------------------------
    def encrypt(self, key, nonce, associated_data, plaintext):
        pass


    #---------------------------------------------------------------
    # decrypt()
    #---------------------------------------------------------------
    def decrypt(self, key, nonce, associated_data, ciphertext):
        return False


#-------------------------------------------------------------------
# main()
#-------------------------------------------------------------------
def main():
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
    sys.exit(main())

#=======================================================================
# EOF pyocb.py
#=======================================================================
