import java.lang.System;
import java.util.Arrays;

public class AuthDecryptor {
	// This class is used to decrypt and authenticate a sequence of values that were encrypted 
	//     by an AuthEncryptor.

	public static final int KeySizeBytes = AuthEncryptor.KeySizeBytes;
	public static final int KeySizeBits = AuthEncryptor.KeySizeBits;

	public static final int NonceSizeBytes = StreamCipher.NonceSizeBytes;

	public StreamCipher streamCiph;
	public PRF macPRF;
	private byte[] ciphertext;
	private byte[] plaintext;
	private byte[] messagemac;
	private byte[] mactext;
	private byte[] mackey;
	private byte[] cryptokey;
	public byte[] input;
	public byte[] inputnonce;

	public AuthDecryptor(byte[] key) {
		assert key.length == KeySizeBytes;
		PRGen keygen = new PRGen(key);
		
		mackey = new byte[32];
		keygen.nextBytes(mackey); // generate a 32 byte mac key from the key

		cryptokey = new byte[24];
		keygen.nextBytes(cryptokey); // generate a 24 byte crypto key from the key
	}

	public byte[] decrypt(byte[] in, byte[] nonce, boolean nonceIncluded) {
		// Decrypt and authenticate the contents of <in>.  The value passed in will normally
		//    have been created by calling encrypt() with the same nonce in an AuthEncryptor 
		//    that was initialized with the same key as this AuthDecryptor.
		// If <nonceIncluded> is true, then the nonce has been included in <in>, and
		//    the value passed in as <nonce> will be disregarded.
		// If <nonceIncluded> is false, then the value of <nonce> will be used.
		// If the integrity of <in> cannot be verified, then this method returns null.   Otherwise it returns 
		//    a newly allocated byte-array containing the plaintext value that was originally 
		//    passed to encrypt().

		if (nonceIncluded) {
			input = Arrays.copyOfRange(in, 0, (in.length - 8));
			inputnonce = Arrays.copyOfRange(in, (in.length - 8), in.length);
		} else {
			input = in.clone();
			inputnonce = nonce;
		}
		ciphertext = Arrays.copyOfRange(in, 0, (input.length - 32));
		messagemac = Arrays.copyOfRange(in, (input.length - 32), input.length);

		macPRF = new PRF(mackey);
		mactext = new byte[32];
		for (int i = 0; i < ciphertext.length; i=i+32){
			mactext = Arrays.copyOfRange(ciphertext, i, i+32);
			mactext = macPRF.eval(mactext);
			macPRF = new PRF(mactext);
		}
		if (!Arrays.equals(mactext, messagemac)) {
			return null;
		}

		streamCiph = new StreamCipher(cryptokey);
		streamCiph.setNonce(inputnonce);

		plaintext = new byte[ciphertext.length];
		streamCiph.cryptBytes(ciphertext, 0, plaintext, 0, ciphertext.length);
		return plaintext;

	}

	public static void main(String[] args){
		byte[] key = TrueRandomness.get();
		byte a = 117;
		byte b = 45;
		byte c = 58;
		byte d = 17;
		byte e = 53;
		byte f = 12;
		byte g = 41;
		byte h = 32;
		byte i = 65;
		byte j = 12;
		byte zero = 0;
		byte[] nonce = new byte[]{a,b,a,a,b,c,g,i};
		byte[] input = new byte[]{a, b, c, d, d, e, e, f, g, };
		System.out.format("Input: %s%n",Arrays.toString(input));
		AuthEncryptor encryptor = new AuthEncryptor(key);
		byte[] encrypted = encryptor.encrypt(input, nonce, true);
		System.out.format("Encrypted: %s%n",Arrays.toString(encrypted));
		
		AuthDecryptor decryptor = new AuthDecryptor(key);
		byte[] decrypted = decryptor.decrypt(encrypted, nonce, true);
		System.out.format("Decrypted: %s%n",Arrays.toString(decrypted));
	}
}