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
package org.vstakhov.cryptobox.crypto;

import static org.vstakhov.cryptobox.Cryptobox.CryptoboxLib.PUBLICKEY_BYTES;
import static org.vstakhov.cryptobox.Cryptobox.CryptoboxLib.SECRETKEY_BYTES;
import static org.vstakhov.cryptobox.Cryptobox.CryptoboxLib.MAC_BYTES;
import static org.vstakhov.cryptobox.Cryptobox.CryptoboxLib.NONCE_BYTES;
import static org.vstakhov.cryptobox.Cryptobox.library;
import static org.vstakhov.cryptobox.crypto.Util.checkLength;
import org.vstakhov.cryptobox.crypto.Key;

public class Box {
    private final byte[] privateKey;
    private final byte[] publicKey;

    public Box(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        checkLength(publicKey, PUBLICKEY_BYTES);
        checkLength(privateKey, SECRETKEY_BYTES);
    }

    public Box(Key publicKey, Key privateKey) {
        this(publicKey.toBytes(), privateKey.toBytes());
    }

    public byte[] encrypt(byte[] nonce, byte[] tag, byte[] message) {
        checkLength(nonce, NONCE_BYTES);
        checkLength(tag, MAC_BYTES);
        library().rspamd_cryptobox_encrypt_inplace(message, 
        		message.length, nonce, publicKey, privateKey, tag);
        
        return message;
    }

    public byte[] decrypt(byte[] nonce, byte[] tag, byte[] ciphertext) {
        checkLength(nonce, NONCE_BYTES);
        checkLength(tag, MAC_BYTES);
        if (!library().rspamd_cryptobox_decrypt_inplace(ciphertext, 
        		ciphertext.length, nonce, publicKey, privateKey, tag)) {
        	throw new RuntimeException("Decryption failed");
        }
        
        return ciphertext;
    }
}
