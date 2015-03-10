package org.vstakhov.cryptobox.crypto;

import static org.junit.Assert.*;
import java.util.Arrays;
import org.junit.Test;
import static org.vstakhov.cryptobox.crypto.Random.randomBytes;

public class RandomTest {

	@Test
	public void testRandomBytes() {
		final int size = 32;
		int i;
		
		for (i = 0; i < 2048; i ++) {
			assertFalse("Should produce different random bytes",
				Arrays.equals(randomBytes(size), randomBytes(size)));
		}
	}

}
