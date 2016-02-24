import java.math.BigInteger;
import java.util.Arrays;

public class KeyExchange {
	public static final int OutputSizeBytes = 256; // IMPLEMENT THIS
	public static final int OutputSizeBits = 8 * OutputSizeBytes;
	public static BigInteger g;
	public static BigInteger p;
	public static BigInteger a;
	public static BigInteger moddedA;
	public static BigInteger moddedB;
	public static BigInteger s;
	public static PRGen myPRGen;

	public KeyExchange(PRGen rand) {
		// Prepares to do a key exchange. rand is a secure pseudorandom generator
		//    that can be used by the implementation.
		//
		// Once the KeyExchange object is created, two operations have to be performed to complete
		// the key exchange:
		// 1.  Call prepareOutMessage on this object, and send the result to the other
		//     participant.
		// 2.  Receive the result of the other participant's prepareOutMessage, and pass it in
		//     as the argument to a call on this object's processInMessage.  
		// For a given KeyExchange object, prepareOutMessage and processInMessage
		// could be called in either order, and KeyExchange should produce the same result regardless.
		//
		// The call to processInMessage should behave as follows:
		//     If passed a null value, then throw a NullPointerException.
		//     Otherwise, if passed a value that could not possibly have been generated
		//        by prepareOutMessage, then return null.
		//     Otherwise, return a "digest" value with the property described below.
		//
		// This code must provide the following security guarantee: If the two 
		//    participants end up with the same non-null digest value, then this digest value
		//    is not known to anyone else.   This must be true even if third parties
		//    can observe and modify the messages sent between the participants.
		// This code is NOT required to check whether the two participants end up with
		//    the same digest value; the code calling this must verify that property.

		myPRGen = rand;
        g = DHParams.g;
        p = DHParams.p;
        a = Proj2Util.generatePrime(myPRGen, OutputSizeBits);
	}

	public byte[] prepareOutMessage() {
		moddedA = g.modPow(a, p);
		return Proj2Util.bigIntegerToBytes(moddedA, OutputSizeBytes);
	}

	public byte[] processInMessage(byte[] inMessage) {
		if (inMessage == null)    throw new NullPointerException();
		if (inMessage.length != OutputSizeBytes) {
			return null;
		}
		moddedB = Proj2Util.bytesToBigInteger(inMessage);
		s = moddedB.modPow(a, p);
		return Proj2Util.bigIntegerToBytes(s, OutputSizeBytes);
	}

	public static void main(String[] argv) {
		byte[] bytearray = new byte[32];
        bytearray[0] = 2;
        bytearray[1] = 14;
        bytearray[2] = 34;
        bytearray[3] = 13;
        bytearray[4] = 43;
        PRGen myPRG = new PRGen(bytearray);
		KeyExchange keyex = new KeyExchange(myPRG);

		byte[] bytearray2 = new byte[32];
        bytearray2[0] = 21;
        bytearray2[1] = 14;
        bytearray2[2] = 12;
        bytearray2[3] = 13;
        bytearray2[4] = 4;
        PRGen myPRG2 = new PRGen(bytearray2);
		KeyExchange keyex2 = new KeyExchange(myPRG2);

		byte[] out1 = keyex.prepareOutMessage();
		byte[] out2 = keyex2.prepareOutMessage();

		System.out.println(Arrays.toString(keyex.processInMessage(out2)));
		System.out.println(Arrays.toString(keyex2.processInMessage(out1)));
	}
}
