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

import static org.vstakhov.cryptobox.crypto.Util.base32Decode;
import static org.vstakhov.cryptobox.crypto.Util.base32Encode;
import static org.vstakhov.cryptobox.crypto.Util.checkLength;
import static org.vstakhov.cryptobox.Cryptobox.CryptoboxLib.PUBLICKEY_BYTES;

public class Key {
	private final byte[] data;
	
	public Key(byte[] raw) {
		this.data = raw;
		checkLength(raw, PUBLICKEY_BYTES);
	}
	
	public Key(String encoded) {
		this.data = base32Decode(encoded);
		checkLength(this.data, PUBLICKEY_BYTES);
	}
	
	public byte[] toBytes() {
		return data;
	}
	
	public String toString() {
		return base32Encode(this.data);
	}
}
