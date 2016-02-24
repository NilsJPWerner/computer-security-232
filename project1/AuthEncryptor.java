import java.lang.System;
import java.util.Arrays;

public class AuthEncryptor {
	// This class is used to compute the authenticated encryption of values.  
	//     Authenticated encryption protects the confidentiality of a value, so that the only 
	//     way to recover the initial value is to do authenticated decryption of the value using the 
	//     same key and nonce that were used to encrypt it.   At the same time, authenticated encryption
	//     protects the integrity of a value, so that a party decrypting the value using
	//     the same key and nonce (that were used to decrypt it) can verify that nobody has tampered with the
	//     value since it was encrypted.

	public static final int KeySizeBytes = 32;   // IMPLEMENT THIS
	public static final int KeySizeBits = KeySizeBytes*8;

	public static final int NonceSizeBytes = StreamCipher.NonceSizeBytes;

	public StreamCipher streamCiph;
	public PRF macPRF;
	private byte[] ciphertext;
	private byte[] mactext;
	private byte[] mackey;
	private byte[] cryptokey;
	public byte[] output;

	public AuthEncryptor(byte[] key) {
		assert key.length == KeySizeBytes;	
		PRGen keygen = new PRGen(key);
		
		mackey = new byte[32];
		keygen.nextBytes(mackey); // generate a 32 byte mac key from the key

		cryptokey = new byte[24];
		keygen.nextBytes(cryptokey); // generate a 24 byte crypto key from the key


	}

	public byte[] encrypt(byte[] in, byte[] nonce, boolean includeNonce) {
		// Encrypts the contents of <in> so that its confidentiality and 
		//    integrity are protected against would-be attackers who do 
		//    not know the key that was used to initialize this AuthEncryptor.
		// Callers are forbidden to pass in the same nonce more than once;
		//    but this code will not check for violations of this rule.
		// The nonce will be included as part of the output iff <includeNonce>
		//    is true.  The nonce should be in plaintext if it is included.
		//
		// This returns a newly allocated byte[] containing the authenticated
		//    encryption of the input.

		streamCiph = new StreamCipher(cryptokey); // create StreamCipher object with cryptokey as input
		streamCiph.setNonce(nonce); // Set the nonce

		ciphertext = new byte[in.length];
		streamCiph.cryptBytes(in, 0, ciphertext, 0, in.length); // encrypt the message to ciphertext

		macPRF = new PRF(mackey);	//Create a PRF for the mac, with mackey as input
		mactext = new byte[32];
		for (int i = 0; i < ciphertext.length; i=i+32){ // pass the ciphertext throught the prf
			mactext = Arrays.copyOfRange(ciphertext, i, i+32);
			mactext = macPRF.eval(mactext);
			macPRF = new PRF(mactext);
		}
		output = streamCiph.concatByteArray(ciphertext, mactext); //concat the resulting 32byte mac with the cipher

		if (includeNonce) {
			return streamCiph.concatByteArray(output, nonce); // concat the nonce to the cipher if includeNonce
		} else {
			return output; // Otherwsie return cipher
		}
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
		byte[] input = new byte[]{};
		System.out.format("Input: %s%n",Arrays.toString(input));
		AuthEncryptor encryptor = new AuthEncryptor(key);
		byte[] encrypted = encryptor.encrypt(input, nonce, true);
		System.out.format("Encrypted: %s%n",Arrays.toString(encrypted));
		byte[] encrypted2 = encryptor.encrypt(input, nonce, false);
		System.out.format("Encrypted no nonce: %s%n",Arrays.toString(encrypted2));
		AuthDecryptor decryptor = new AuthDecryptor(key);
		byte[] decrypted = decryptor.decrypt(encrypted, nonce, true);
		System.out.format("Decrypted: %s%n",Arrays.toString(decrypted));
	}
}