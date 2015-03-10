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
import static org.vstakhov.cryptobox.Cryptobox.library;
import org.vstakhov.cryptobox.crypto.Key;

public class KeyPair {
	private byte[] publicKey;
	private final byte[] secretKey;
	
	public KeyPair() {
		this.secretKey = new byte[SECRETKEY_BYTES];
		this.publicKey = new byte[PUBLICKEY_BYTES];
		library().rspamd_cryptobox_keypair(publicKey, secretKey);
	}
	
	public Key pubKey() {
		return new Key(this.publicKey);
	}
	
	public Key privKey() {
		return new Key(this.secretKey);
	}
}
