import java.math.BigInteger;
import java.util.Arrays;

public class RSAKey {
    private BigInteger exponent;
    private BigInteger modulus;
    
    private static final int oaepK0 = 32;
	private static final int oaepK1 = 32;

    public RSAKey(BigInteger theExponent, BigInteger theModulus) {
        exponent = theExponent;
        modulus = theModulus;
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public byte[] encrypt(byte[] plaintext, PRGen prgen) {
        if (plaintext == null)    throw new NullPointerException();
        if (plaintext.length > maxPlaintextLength()) return null;
        byte[] oaep = encodeOaep(plaintext, prgen);
        BigInteger cipher = Proj2Util.bytesToBigInteger(oaep);
        cipher = cipher.modPow(exponent, modulus);
        return Proj2Util.bigIntegerToBytes(cipher, oaep.length);
    }

    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null)    throw new NullPointerException();
        BigInteger message = Proj2Util.bytesToBigInteger(ciphertext);
        message = message.modPow(exponent, modulus);
        byte[] unpadded = decodeOaep(Proj2Util.bigIntegerToBytes(message, ciphertext.length));
        return unpadded;
    }

    public byte[] sign(byte[] message, PRGen prgen) {
        // Create a digital signature on <message>. The signature need
        //     not contain the contents of <message>--we will assume
        //     that a party who wants to verify the signature will already
        //     know which message this is (supposed to be) a signature on.
        byte[] hash = Proj2Util.stretchedHash(message, 256);
        BigInteger biginthash = Proj2Util.bytesToBigInteger(hash);
        biginthash = biginthash.modPow(exponent, modulus);
        return Proj2Util.bigIntegerToBytes(biginthash, message.length);
    }

    public boolean verifySignature(byte[] message, byte[] signature) {
        // Verify a digital signature. Returns true if  <signature> is
        //     a valid signature on <message>; returns false otherwise.
        //     A "valid" signature is one that was created by calling
        //     <sign> with the same message, using the other RSAKey that
        //     belongs to the same RSAKeyPair as this object.
        if ((message == null) || (signature == null))    throw new NullPointerException();
        byte[] hash = Proj2Util.stretchedHash(message, 256);
        BigInteger biginthash = Proj2Util.bytesToBigInteger(hash);
        BigInteger bigintsig = Proj2Util.bytesToBigInteger(signature);
        bigintsig = bigintsig.modPow(exponent, modulus);
        return biginthash.equals(bigintsig);
    }

    public int maxPlaintextLength() {
        // Return the largest N such that any plaintext of size N bytes
        //      can be encrypted with this key
        int n = (modulus.toByteArray()).length;
        return n - oaepK0 - oaepK1 -2;
    }
       
    // The next four methods are public to help us grade the assignment. In real life, these would
    // be private methods as there's no need to expose these methods as part of the public API
    
    public byte[] encodeOaep(byte[] input, PRGen prgen) {
        byte[] message = input.clone();
        int messagelength = maxPlaintextLength()+1;
        int oaeplength = messagelength + oaepK1;
        if (message.length > messagelength) {
            return null;     
        }
        else {
            message = addPadding(message);          // need to make sure this returns byte[] messagelength
        }
        byte[] paddedmessage = new byte[oaeplength]; // new array n-k0 size filled with 0s
        System.arraycopy(message, 0, paddedmessage, 0, messagelength); // put message in

        byte[] r = new byte[oaepK0];
        prgen.nextBytes(r); // get r 32 random bytes.
        PRGen g = new PRGen(r); // Have PRG G seeded from r
        byte[] randomarray = new byte[oaeplength]; 
        g.nextBytes(randomarray); // get random bits, length of the padded message
        for (int i = 0; i < oaeplength; i++) { // XOR with the message
            paddedmessage[i] = (byte) (randomarray[i] ^ paddedmessage[i]);
        }

        byte[] hashed = Proj2Util.hash(paddedmessage, 0, oaepK0); //hash message to k0 bytes
        for (int i = 0; i < oaepK0; i++) {  //XOR hash with r
            hashed[i] = (byte) (hashed[i] ^ r[i]);   
        }
        byte[] retarray = concatByteArray(paddedmessage, hashed); // concatonate them
        return retarray;
    }
    
    public byte[] decodeOaep(byte[] input) {
        byte[] x = new byte[input.length - oaepK0];
        byte[] y = new byte[oaepK0];
        System.arraycopy(input, 0, x, 0, input.length - oaepK0);
        System.arraycopy(input, input.length - oaepK1, y, 0, oaepK0);

        byte[] hashed = Proj2Util.hash(x, 0, oaepK0);
        byte[] r = new byte[oaepK0];
        for (int i = 0; i < oaepK0; i++) { 
            r[i] = (byte) (hashed[i] ^ y[i]);   
        }
        PRGen g = new PRGen(r);
        byte[] randomarray = new byte[input.length - oaepK0]; 
        g.nextBytes(randomarray);
        byte[] paddedmessage = new byte[input.length - oaepK0];
        for (int i = 0; i < (input.length - oaepK0); i++) { // XOR with the message
            paddedmessage[i] = (byte) (randomarray[i] ^ x[i]);
        }
        byte[] ret = new byte[input.length - oaepK0 - oaepK1];
        System.arraycopy(paddedmessage, 0, ret, 0, input.length - oaepK0 - oaepK1);
        return removePadding(ret);
    }
    
    public byte[] addPadding(byte[] input) {
        //Pads a message that is under n - k0 - k1 length bytes
        // Throws exception if the input is larger than n - k0 - k1
        int messagebitlength = maxPlaintextLength()+1;
        if (input.length > messagebitlength) {
            throw new NullPointerException();
        }
        byte[] padded = new byte[messagebitlength];
        System.arraycopy(input, 0, padded, 0, input.length);
        padded[messagebitlength-1] = (byte) (messagebitlength - input.length);
        return padded;
    }
    
    public byte[] removePadding(byte[] input) {
        // unpads a message
        // Throws exception if the input is not length n - k0 - k1
        int messagebitlength = maxPlaintextLength()+1;
        if (input.length != messagebitlength) {
            throw new NullPointerException();
        }
        int padding = (int) input[messagebitlength-1];
        byte[] unpadded = new byte[messagebitlength-padding];
        System.arraycopy(input, 0, unpadded, 0, messagebitlength-padding);
        return unpadded;
    }

    public byte[] concatByteArray(byte[] a, byte[] a2){
        byte[] newa = new byte[a.length + a2.length];
        System.arraycopy(a, 0, newa, 0, a.length);
        System.arraycopy(a2, 0, newa, a.length, a2.length);
        return newa;
    }

    public static void main(String[] args) {
        // byte[] bytearray = new byte[32];
        // bytearray[0] = 2;
        // bytearray[1] = 14;
        // bytearray[2] = 34;
        // bytearray[3] = 13;
        // bytearray[4] = 43;
        // PRGen myPRG = new PRGen(bytearray);
        // RSAKeyPair key = new RSAKeyPair(myPRG, 1024);
        // bytearray[5] = 12;
        // PRGen myPRG2 = new PRGen(bytearray);
        // //BigInteger[] primes = key.getPrimes();
        // //System.out.format("exponent1 is %d, length: %d\n", key.getPrivateKey().getExponent(), key.getPrivateKey().getExponent().bitLength());
        // //System.out.format("modulus is %d, length: %d\n", key.getPrivateKey().getModulus(), key.getPrivateKey().getModulus().bitLength());
        // byte[] message = new byte[]{15, -20, 119, -17, 87, 75, 121, -63, -4, 108, -68, -44, -57, -118, -124, 33, -80, -25, 97, 12, -10, 6, -76, 86, 44, 118, -55, -101, -106, -115, -5, -84, 99, -1, 28, -50, -46, 8, 53, 5, -108, -101, 0, -22, -82, -23, -45, 51, -87, 92, 73, 67, 81, 106, 82, -47, -71, -110, -101, -66, 15, 105, -118, -115, 89, 69, 74, 65, -31, -99, 19, 112, 9, 110, 127, -66, 90, -94, 40, 43, 4, 99, -128, 92, 54, 6, -9, 108, -40, -3, -26, -13, 83, 68, -99, 1, -93, 17, -87, -85, 87, -96, 0, -58, -12, 76, 12, 9, 83, 4, 72, -80, -128, 84, 68, -10, 49, 35, -49, -16, -106, -80, -20, -35, 17, -10, 110, 58, -77, -32, -39, 125, 68, -23, -111, -4, 113, 64, -69, 0, -105, -70, -120, -48, -21, 10, 83, 108, -59, 90, 23, -2, -44, 74, 27, 82, -106, 16, -95, 76, -114, 92, 46, -1, -66, 101, 39, 114, 119, -20, -40, -45, -80, -48, -66, 107, -12, 18, -94, -97, 73, 111, 9, 80, -22, -125, -57, -116};
        // System.out.println(message.length);

        // byte[] cipher = key.getPublicKey().encrypt(message, myPRG2);
        // //System.out.println(Arrays.toString(cipher));
        // System.out.println(cipher.length);
        // byte[] sig = key.getPrivateKey().sign(cipher, myPRG2);
        // //System.out.println(sig.length);
        // //System.out.println(key.getPublicKey().verifySignature(cipher, sig));

        // byte[] decoded = key.getPrivateKey().decrypt(cipher);
        // System.out.println(Arrays.toString(decoded));
    }
}
