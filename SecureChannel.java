
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
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

	private byte[] sharedSecretKey;
	private PRGen nonceGenerator;
	private int messagesSent = 0;
	private int messagesReceived = 0;

	public SecureChannel(InputStream inStr, OutputStream outStr, 
			PRGen rand, boolean iAmServer,
			RSAKey serverKey) throws IOException {
		// if iAmServer==false, then serverKey is the server's *public* key
		// if iAmServer==true, then serverKey is the server's *private* key

		super(inStr, outStr);

		byte[] key_msg;
		byte[] signature;
		RSAKey pub_k;
		RSAKey priv_k;
		Proj2Util p2u = new Proj2Util();
		KeyExchange key_xc = new KeyExchange(rand);
        key_msg = key_xc.prepareOutMessage();
        // random number to send for freshness
        byte[] random_num = new byte[32];
        rand.nextBytes(random_num);

        if (iAmServer == true){
        	// get public key from client
        	byte[] client_exp = super.receiveMessage();
        	byte[] client_mod = super.receiveMessage();
        	BigInteger bi_client_exp = p2u.bytesToBigInteger(client_exp);
        	BigInteger bi_client_mod = p2u.bytesToBigInteger(client_mod);
        	pub_k = new RSAKey(bi_client_exp, bi_client_mod);
        	priv_k = serverKey;
        	// sign the DH key exchange message
        	signature = serverKey.sign(key_msg, rand);

        }
        else{
        	pub_k = serverKey;
        	// create client key pair
        	RSAKeyPair client_kp = new RSAKeyPair(rand, 1024);
        	RSAKey client_privk = client_kp.getPrivateKey();
        	RSAKey client_pubk = client_kp.getPublicKey();
        	priv_k = client_privk;
        	// send public key to server
        	BigInteger bi_pubk_exp = client_pubk.getExponent();
        	BigInteger bi_pubk_mod = client_pubk.getModulus();
        	byte[] pubk_exp = p2u.bigIntegerToBytes(bi_pubk_exp, bi_pubk_exp.bitLength()/8+1);
			byte[] pubk_mod = p2u.bigIntegerToBytes(bi_pubk_mod, bi_pubk_mod.bitLength()/8+1); 
			super.sendMessage(pubk_exp);
			super.sendMessage(pubk_mod);
			// sign the DH key exchange message
			signature = client_privk.sign(key_msg, rand);
        }
        // send encrypted random number
        byte[] encrypted_random_num = pub_k.encrypt(random_num, rand);
        super.sendMessage(encrypted_random_num);
        // get other person's random number
        byte[] encrypted_other_random_num = super.receiveMessage();
        byte[] other_random_num = priv_k.decrypt(encrypted_other_random_num);

		super.sendMessage(key_msg);
		// get DH key exchange message from other
        byte[] in_msg = super.receiveMessage();
		byte[] sharedSecret = key_xc.processInMessage(in_msg);
		// send my signature
		super.sendMessage(signature);
		// verify other person's signature
		byte[] received_signature = super.receiveMessage();
		if (pub_k.verifySignature(in_msg, received_signature)==false){
			throw new IOException("Signature not valid!");
		}

		// hash the random numbers and the shared Secret to get master secret
		byte[] total_secret = new byte[32+32+sharedSecret.length];
		byte[] random_numbers = new byte[32+32];
		if (iAmServer == true){
			System.arraycopy(random_num, 0, random_numbers, 0, 32);
			System.arraycopy(other_random_num, 0, random_numbers, 32, 32);
		}
		else {
			System.arraycopy(other_random_num, 0, random_numbers, 0, 32);
			System.arraycopy(random_num, 0, random_numbers, 32, 32);
		}
		System.arraycopy(random_numbers, 0, total_secret, 0, 64);
		System.arraycopy(sharedSecret, 0, total_secret, 64, sharedSecret.length);

		byte[] hashed_secret = p2u.hash(total_secret);
		sharedSecretKey = hashed_secret;

		// finished msg = "client/server finished" and random numbers
		// verify that we have the same shared secret by sending PRF_k(finished_message)
		PRF prf = new PRF(hashed_secret);
		byte[] cfin_bytes = "client finished".getBytes();
		byte[] sfin_bytes = "server finished".getBytes();
		byte[] cfin_and_msgs = new byte[64+cfin_bytes.length];
		byte[] sfin_and_msgs = new byte[64+sfin_bytes.length];
		System.arraycopy(random_numbers, 0, cfin_and_msgs, 0, 64);
		System.arraycopy(cfin_bytes, 0, cfin_and_msgs, 64, cfin_bytes.length);
		System.arraycopy(random_numbers, 0, sfin_and_msgs, 0, 64);
		System.arraycopy(sfin_bytes, 0, sfin_and_msgs, 64, sfin_bytes.length);

		byte[] hashed_cfin = prf.eval(cfin_and_msgs);
		byte[] hashed_sfin = prf.eval(sfin_and_msgs);

		if (iAmServer == true){
			super.sendMessage(hashed_sfin);
			byte[] received_hashed_cfin = super.receiveMessage();
			if (Arrays.equals(received_hashed_cfin, hashed_cfin) == false){
				throw new IOException("PRF produced messages do not match!");
			}
		}
		else{
			super.sendMessage(hashed_cfin);
			byte[] received_hashed_sfin = super.receiveMessage();
			if (Arrays.equals(received_hashed_sfin, hashed_sfin) == false){
				throw new IOException("PRF produced messages not match!");
			}
		}
		// use a prgen for generating nonces for encryption
		// if we use the same nonceGenerator, then if a mitm tries to use
		// the same nonce twice, we will not expect to be encrypted with
		// that nonce and so the HMAC will seem false, -> null
		nonceGenerator = new PRGen(sharedSecretKey);
	}

	public void sendMessage(byte[] message) throws IOException {
		
		AuthEncryptor ae = new AuthEncryptor(sharedSecretKey);
		byte[] nonce = new byte[StreamCipher.NonceSizeBytes];
		int msg_length = message.length;
		byte[] msg_and_count = new byte[msg_length +4];
		// add counter to the message
		byte[] count = new byte[4];	
        count[0] = (byte)((messagesSent >>> 24) & 0XFF);
        count[1] = (byte)((messagesSent >>> 16) & 0XFF);
        count[2] = (byte)((messagesSent >>> 8) & 0XFF);
        count[3] = (byte)(messagesSent & 0XFF);

        System.arraycopy(message, 0, msg_and_count, 0, msg_length);
        System.arraycopy(count, 0, msg_and_count, msg_length, 4);

		nonceGenerator.nextBytes(nonce);
		byte[] encrypted_msg = ae.encrypt(msg_and_count,nonce,true);
		super.sendMessage(encrypted_msg);
		messagesSent += 1;
	}

	public byte[] receiveMessage() throws IOException {

		AuthDecryptor ad = new AuthDecryptor(sharedSecretKey);
		byte[] encrypted_msg = super.receiveMessage();
		byte[] decrypted_msg = ad.decrypt(encrypted_msg, null, true);
		if (decrypted_msg == null){
			throw new IOException("invalid message received");
		}
		int count;
		int msg_length = decrypted_msg.length;

		byte[] msg = Arrays.copyOfRange(decrypted_msg, 0, msg_length-4);
		byte[] byte_count = Arrays.copyOfRange(decrypted_msg, msg_length-4, msg_length);

        count = byte_count[0] << 24 | (byte_count[1] & 0xff) << 16 | (byte_count[2] & 0xff) << 8 | (byte_count[3] & 0xff);
		if (count != messagesReceived){
			return null;
		}
		messagesReceived += 1;
		SecureChannelUtils.printTaggedByteArray("received: ", msg, "\n\n");

		return msg;
	}

}
