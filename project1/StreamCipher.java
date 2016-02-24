import java.util.Arrays;
import java.lang.System;

public class StreamCipher {
	// This class encrypts or decrypts a stream of bytes, using a stream cipher.

	public static final int KeySizeBytes = 24;  // IMPLEMENT THIS
	public static final int KeySizeBits = KeySizeBytes*8;

	public static final int NonceSizeBytes = 8;
	public static final int NonceSizeBits = NonceSizeBytes*8;

	private byte randombyte;
	private byte[] nonce;
	private static byte[] originalkey;
	private byte[] seed;
	private PRGen prg;


	public StreamCipher(byte[] key) {
		// <key> is the key, which must be KeySizeBytes bytes in length.

		assert key.length == KeySizeBytes;
		originalkey = key.clone();
		prg = new PRGen(key);
		// IMPLEMENT THIS
	}

	public void setNonce(byte[] arr, int offset){
		// Reset to initial state, and set a new nonce.
		// The nonce is in arr[offset] thru arr[offset+NonceSizeBytes-1].
		// It is an error to call setNonce with the same nonce
		//    more than once on a single StreamCipher object.
		// StreamCipher does not check for nonce uniqueness;
		//    that is the responsibility of the caller.

		// IMPLEMENT THIS
		byte[] newnonce = Arrays.copyOfRange(arr, offset, (offset+NonceSizeBytes));
		assert nonce != newnonce;
		assert newnonce.length == NonceSizeBytes;

		nonce = newnonce;
		seed = concatByteArray(originalkey, nonce);

		prg = new PRGen(seed);
	}

	public byte[] concatByteArray(byte[] a, byte[] a2){
		byte[] newa = new byte[a.length + a2.length];
		System.arraycopy(a, 0, newa, 0, a.length);
		System.arraycopy(a2, 0, newa, a.length, a2.length);
		return newa;
	}

	public void setNonce(byte[] nonce) {
		// Reset to initial state, and set a new nonce
		// It is an error to call setNonce with the same nonce
		//    more than once on a single StreamCipher object.
		// StreamCipher does not check for nonce uniqueness;
		//    that is the responsibility of the caller.

		assert nonce.length == NonceSizeBytes;
		setNonce(nonce, 0);
	}

	public byte cryptByte(byte in) {
		// Encrypt/decrypt the next byte in the stream
		randombyte = (byte) prg.next(8);
		return (byte) (randombyte ^ in);
	}

	public void cryptBytes(byte[] inBuf, int inOffset, 
			byte[] outBuf, int outOffset, 
			int numBytes) {
		// Encrypt/decrypt the next <numBytes> bytes in the stream
		// Take input bytes from inBuf[inOffset] thru inBuf[inOffset+numBytes-1]
		// Put output bytes at outBuf[outOffset] thru outBuf[outOffset+numBytes-1];


		for (int i = 0; i < numBytes; i++){
			outBuf[outOffset + i] = cryptByte(inBuf[inOffset + i]);
		}
	}

	public static void main(String[] args) {
		byte byte_a = 123;
		byte byte_b = 12;
		byte byte_c = 4;
		byte byte_d = 10;
		byte[] bytearray = new byte[] { byte_a, byte_b, byte_c, byte_d};
		StreamCipher stream1 = new StreamCipher(bytearray);
		System.out.format("originalbyte is %d\n", byte_a);
		byte cryptbyte = stream1.cryptByte(byte_a);
		System.out.format("cryptbyte is %d\n", cryptbyte);

		StreamCipher stream2 = new StreamCipher(bytearray);
		byte uncryptbyte = stream2.cryptByte(cryptbyte);
		System.out.format("uncryptbyte is %d\n", uncryptbyte);

		System.out.format("\n");

		// byte byte_i = 12;
		// byte byte_j = 34;
		// byte byte_k = 56;
		// byte byte_l = 78;
		// byte byte_m = 90;
		// byte[] originalbytes = new byte[] { byte_i, byte_j, byte_k, byte_l, byte_m};
		// System.out.format("originalbytes is %s\n", Arrays.toString(originalbytes));
		
		// byte[] nonce = new byte[] { byte_j, byte_m};
		// stream1.setNonce(nonce);
		// byte[] cryptbytes = new byte[5];
		// stream1.cryptBytes(originalbytes, 0, cryptbytes, 0, 5);
		// System.out.format("cryptbytes is %s\n", Arrays.toString(cryptbytes));

		// byte[] uncryptbytes = new byte[4];
		// stream2.cryptBytes(cryptbytes, 0, uncryptbytes, 0, 4);
		// System.out.format("uncryptbytes is %s\n", Arrays.toString(uncryptbytes));
	}
}
