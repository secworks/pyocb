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
    def __init__(self, verbose = False):
        pass

    def encipher(self, key, block):
        if keylen not in [128, 256]:
            print("Unsupported key length: %d bits" % keylen)
            return
        self.keylen = keylen

    def decipher(self, key, block):
        return block

    def __key_init(self, key):
        pass

    def __self_test():
        pass


#-------------------------------------------------------------------
# main()
#-------------------------------------------------------------------
def main():
    my_aes = AES()
    my_aes.__self_test()


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
