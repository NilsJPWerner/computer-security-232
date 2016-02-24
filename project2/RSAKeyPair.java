import java.math.BigInteger;

public class RSAKeyPair {
	private RSAKey publicKey;
	private RSAKey privateKey;
	private BigInteger prime1;
	private BigInteger prime2;

	public RSAKeyPair(PRGen rand, int numBits) {
		// Create an RSA key pair.  rand is a PRGen that this code can use to get pseudorandom
		//     bits.  numBits is the size in bits of each of the primes that will be used.

		prime1 = Proj2Util.generatePrime(rand, numBits);
		prime2 = Proj2Util.generatePrime(rand, numBits);

		BigInteger n = prime1.multiply(prime2);
		BigInteger k = ((n.subtract(prime1)).subtract(prime2)).add(BigInteger.valueOf(1));
		int[] primearray = {65537, 66373, 66377, 66383, 104761, 104773, 104779, 246569, 246577, 246599, 369793};
		BigInteger e = BigInteger.valueOf(65537);
		for (int i = 0; i<primearray.length; i++){
			if (k.mod(BigInteger.valueOf(primearray[i])).compareTo(BigInteger.valueOf(0)) != 0) {
				e = BigInteger.valueOf(primearray[i]);
				break;
			}
		}
		BigInteger d = e.modInverse(k);
		publicKey = new RSAKey(e, n);
		privateKey = new RSAKey(d, n);
	}

	public RSAKey getPublicKey() {
		return publicKey;
	}

	public RSAKey getPrivateKey() {
		return privateKey;
	}

	public BigInteger[] getPrimes() {
		// Returns an array containing the two primes that were used in key generation.
		//   In real life we don't always keep the primes around.
		//   But including this helps us grade the assignment.
		BigInteger[] ret = new BigInteger[2];
        ret[0] = prime1; // IMPLEMENT THIS
        ret[1] = prime2;
		return ret;
	}
}
