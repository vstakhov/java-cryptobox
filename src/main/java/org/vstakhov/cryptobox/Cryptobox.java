/*
 * Copyright (c) 2015 Vsevolod Stakhov
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */
package org.vstakhov.cryptobox;

import jnr.ffi.LibraryLoader;
import jnr.ffi.annotations.In;
import jnr.ffi.annotations.Out;
import jnr.ffi.types.size_t;

public class Cryptobox {

    public static CryptoboxLib library() {
    	CryptoboxLib lib = SingletonHolder.LIB_INSTANCE;

        return lib;
    }

    private static final String LIBRARY_NAME = "cryptobox";

    private static final class SingletonHolder {
        public static final CryptoboxLib LIB_INSTANCE = 
        		LibraryLoader.create(CryptoboxLib.class)
                .search("/usr/local/lib")
                .search("/opt/local/lib")
                .search("lib")
                .load(LIBRARY_NAME);

    }

    private Cryptobox() {
    }

    public interface CryptoboxLib {

        public int rspamd_cryptobox_init();

        public static final int PUBLICKEY_BYTES = 32;
        public static final int SECRETKEY_BYTES = 32;

        /**
         * Generate new keypair
         * @param publicKey public key buffer
         * @param secretKey secret key buffer
         */
        public int rspamd_cryptobox_keypair(@Out byte[] publicKey, @Out byte[] secretKey);

        public static final int NONCE_BYTES = 24;
        public static final int MAC_BYTES = 16;

        /**
         * Set the specified buffer with cryptographical random data
         * @param buffer buffer for random data
         * @param size size of buffer
         */
        public void rspamd_randombytes(@Out byte[] buffer, @size_t long size);

        /**
         * Encrypt segments of data inplace adding signature to sig afterwards
         * @param len data buffer (modified inplace)
         * @param publicKey remote pubkey
         * @param privateKey local secret key
         * @param sig output signature
         */
        public void rspamd_cryptobox_encrypt_inplace(@Out byte[] data, 
        		@size_t long len,
        		@In byte[] nonce,
        		@In byte[] publicKey, 
        		@In byte[] privateKey, 
        		@Out byte[] sig);
        /**
         * Decrypt and verify data chunk inplace
         * @param data data to decrypt
         * @param len lenght of data
         * @param publicKey remote pubkey
         * @param privateKey local privkey
         * @param sig signature input
         * @return TRUE if input has been verified successfully
         */
        public boolean rspamd_cryptobox_decrypt_inplace (@Out byte[] data, 
        		@size_t long len,
        		@In byte[] nonce,
        		@In byte[] publicKey, 
        		@In byte[] privateKey, 
        		@In byte[] sig);
        
        public static final int HASH_BYTES = 64;
        
        /**
         * Calculates hash for the input data (currently blake2b hash)
         * @param buf buffer to calculate checksum
         * @param size size of buffer
         * @param out output buffer
         */
        public void rspamd_cryptobox_hash (@In byte[] buf, @size_t long size,
            @Out byte[] out);
    }

    public static int init() {
        return library().rspamd_cryptobox_init();
    }
}