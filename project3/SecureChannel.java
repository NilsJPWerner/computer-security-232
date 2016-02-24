
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

public class SecureChannel extends InsecureChannel {
	// This is just like an InsecureChannel, except that it provides 
	//    authenticated encryption for the messages that pass
	//    over the channel.   It also guarantees that messages are delivered 
	//    on the receiving end in the same order they were sent (returning
	//    null otherwise).  Also, when the channel is first set up,
	//    the client authenticates the server's identity, and the necessary
	//    steps are taken to detect any man-in-the-middle (and to close the
	//    connection if a MITM is detected).
	//
	// The code provided here is not secure --- all it does is pass through
	//    calls to the underlying InsecureChannel.

	public static PRGen prg;
	public static byte[] aesKey;
	public static AuthEncryptor aesEncrypt;
	public static AuthDecryptor aesDecrypt;
	public static byte[] nonce;
	public static byte[] encryptedMessage;
	public static byte[] decryptedMessage;

	public SecureChannel(InputStream inStr, OutputStream outStr, 
			PRGen rand, boolean iAmServer,
			RSAKey serverKey) throws IOException {
		// if iAmServer==false, then serverKey is the server's *public* key
		// if iAmServer==true, then serverKey is the server's *private* key
		super(inStr, outStr);

		KeyExchange keyex;
		byte[] history;
		byte[] receivedgmod;
		byte[] recievedHistory;

		prg = rand; // save the prg
		keyex = new KeyExchange(prg); // create new keyexchange object
		byte[] gmod = keyex.prepareOutMessage(); // get gmod for server and client

		if (iAmServer) {
			byte[] signature = serverKey.sign(gmod, prg); // sign gmod with privatekey
			byte[] sigLength = new byte[1];
			sigLength[0] = (byte) (signature.length-200); // get length of signature

			byte[] signedmessage = concatByteArray(signature, gmod); // concat signature and gmod
			signedmessage = concatByteArray(sigLength, signedmessage); // concat siglength to that
			
			receivedgmod = super.receiveMessage(); //recieve gmod from client
			history = receivedgmod.clone(); // put receivedgmod into history
			
			super.sendMessage(signedmessage); // send signedmessage to client
			history = concatByteArray(history, signedmessage); // add signedmessage to history
		}
		else {
			super.sendMessage(gmod);  // send client gmod
			history = gmod.clone(); // put gmod into history

			byte[] receivedMessage = super.receiveMessage();  // recieve server gmod + sig
			history = concatByteArray(history, receivedMessage);  // add recieved message to history
			
			int sigLength = ((int) receivedMessage[0])+200; // set siglength to first bit

			byte[] serversig = new byte[sigLength]; // create byte array of length sigLength
			System.arraycopy(receivedMessage, 1, serversig, 0, sigLength); // copy signature to array
			receivedgmod = new byte[receivedMessage.length - (1 + sigLength)]; // create byte array message length
			System.arraycopy(receivedMessage, sigLength+1, receivedgmod, 0, receivedgmod.length); // copy message to array
			
			if (!serverKey.verifySignature(receivedgmod, serversig)) {
				super.close(); // close if signature is not verified
			}
		}
		byte[] s = keyex.processInMessage(receivedgmod); // both sides have the secret s
		aesKey = Proj2Util.hash(s, 0, AuthEncryptor.KeySizeBytes); // hash the secret s to the right length key
		aesEncrypt = new AuthEncryptor(aesKey); // Create a new authEncryptor object with that key
		aesDecrypt = new AuthDecryptor(aesKey); // Create a new Decryptor object with that key

		nonce = new byte[StreamCipher.NonceSizeBytes];
		prg.nextBytes(nonce); // create a nonce

		history = Proj2Util.hash(history, 0, 32); // hash history

		if (iAmServer) {
			byte[] messageAddition = new byte[] {1,}; // make the server message 1
			byte[] addedHistory = concatByteArray(messageAddition, history); // append that to history

			byte[] clientHistory = super.receiveMessage(); // recieve encrypted history from client
			recievedHistory = aesDecrypt.decrypt(clientHistory, nonce, true); // decrypt history 

			super.sendMessage(aesEncrypt.encrypt(addedHistory, nonce, true));
		}
		else {
			byte[] messageAddition = new byte[] {2,}; // make client message addition 2
			byte[] addedHistory = concatByteArray(messageAddition, history); // append that to history
			
			super.sendMessage(aesEncrypt.encrypt(addedHistory, nonce, true)); // send to server

			byte[] serverHistory = super.receiveMessage(); // recieve encrypted history from server
			recievedHistory = aesDecrypt.decrypt(serverHistory, nonce, true); // decrypt history 
		}
		byte[] processedHistory = new byte[recievedHistory.length-1]; 
		System.arraycopy(recievedHistory, 1, processedHistory, 0, 32); // remove first bit from recieved history
		if (!Arrays.equals(history, processedHistory)) {
			super.close(); // if they don't match close
		}
	}

	public byte[] concatByteArray(byte[] a, byte[] a2){
    	byte[] newa = new byte[a.length + a2.length];
        System.arraycopy(a, 0, newa, 0, a.length);
        System.arraycopy(a2, 0, newa, a.length, a2.length);
        return newa;
    }

	public void sendMessage(byte[] message) throws IOException {
		nonce = new byte[StreamCipher.NonceSizeBytes];
		prg.nextBytes(nonce); // create a nonce
		encryptedMessage = aesEncrypt.encrypt(message, nonce, true);
		super.sendMessage(encryptedMessage);    // IMPLEMENT THIS
	}

	public byte[] receiveMessage() throws IOException {
		encryptedMessage = super.receiveMessage();
		if (encryptedMessage == null) {
			return null;
		}
		decryptedMessage = aesDecrypt.decrypt(encryptedMessage, nonce, true);
		return decryptedMessage;   // IMPLEMENT THIS
	}
}
