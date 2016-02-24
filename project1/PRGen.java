
import java.util.Random;
import java.math.BigInteger;
import java.util.Arrays;


public class PRGen extends Random {
	// This implements a pseudorandom generator.  It extends java.util.Random, which provides
	//     a useful set of utility methods that all build on next(.).  See the documentation for
	//     java.util.Random for an explanation of what next(.) is supposed to do.
	// If you're calling a PRGen, you probably want to call methods of the Random superclass.
	//
	// There are two requirements on a pseudorandom generator.  First, it must be pseudorandom,
	//     meaning that there is no (known) way to distinguish its output from that of a
	//     truly random generator, unless you know the key.  Second, it must be deterministic, 
	//     which means that if two programs create generators with the same seed, and then
	//     the two programs make the same sequence of calls to their generators, they should
	//     receive the same return values from all of those calls.
	// Your generator must have an additional property: backtracking resistance.  This means that if an
	//     adversary is able to observe the full state of the generator at some point in time, that
	//     adversary cannot reconstruct any of the output that was produced by previous calls to the
	//     generator.
	
	public static final int KeySizeBytes = 32;   // IMPLEMENT THIS  -  32?
	public static final int KeySizeBits = KeySizeBytes*8;
	public static byte[] seed = new byte[KeySizeBytes];
	public PRGen(byte[] key) {
		super();
		assert key.length == KeySizeBytes;
		seed = key.clone();

		// IMPLEMENT THIS
	}

	protected int next(int bits) {
		// For description of what this is supposed to do, see the documentation for 
		//      java.util.Random, which we are subclassing.

		PRF currentPRF = new PRF(seed);
		seed = currentPRF.eval(seed).clone();
		int outint = new BigInteger(seed).intValue();
		if (bits >= 32) {
			return outint;
		}
		return outint & (~(~0 << bits));
	}

	public static void main(String[] args) {
		byte byte_a = 124;
		byte byte_b = 12;
		byte byte_c = 4;
		byte byte_d = 10;
		byte[] bytearray = new byte[] { byte_a, byte_b, byte_c, byte_d};
		PRGen myPRG = new PRGen(bytearray);
		int out = myPRG.next(32);
		System.out.format("Number is %d\n", out);

		PRGen myPRG2 = new PRGen(bytearray);
		int out2 = myPRG2.next(32);
		System.out.format("Number is %d\n", out2);
	}
}