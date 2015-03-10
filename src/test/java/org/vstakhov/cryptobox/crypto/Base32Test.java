package org.vstakhov.cryptobox.crypto;

import static org.junit.Assert.*;
import static org.vstakhov.cryptobox.crypto.Random.randomBytes;
import org.junit.Test;
import java.util.Random;

public class Base32Test {

	@Test
	public void testBase32Encode() {
		String st = Util.base32Encode("test123".getBytes());
		assertEquals("wm3g84fg13cy", st);
	}

	@Test
	public void testBase32Decode() {
		byte[] dec = Util.base32Decode("wm3g84fg13cy");
		String st = new String(dec);
		assertEquals("test123", st);
	}
	
	@Test
	public void fuzzTest() {
		Random r = new Random();
		int i, len;
		
		
		for (i = 0; i < 2048; i ++) {
			len = r.nextInt(2048) + 1;
			byte[] buf = randomBytes(len);
			String st = Util.base32Encode(buf);
			byte[] dec = Util.base32Decode(st);
			assertArrayEquals(buf, dec);
		}
	}

}
