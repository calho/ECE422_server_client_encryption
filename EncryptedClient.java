import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;




public class EncryptedClient {
	static Socket socket;
	static ObjectOutputStream out;
	static ObjectInputStream in;
	
	private static BigInteger g = new BigInteger("5", 16);

	private static BigInteger p = new BigInteger("23", 16);
	
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, ClassNotFoundException {

    	MyEncrypt encrypter = new MyEncrypt();
    	System.loadLibrary("encrypt");
    	MyDecrypt decrypter = new MyDecrypt();
    	System.loadLibrary("decrypt");
    	
    	String test = "Hello World";
    	
    	
    	
		try {
			    socket = new Socket("localhost", 16000);
			    out = new ObjectOutputStream(socket.getOutputStream());
			    in = new ObjectInputStream(socket.getInputStream());
			    System.out.println("connected on client side");
			    
//			    DHParameterSpec dhParameterSpec = new DHParameterSpec(p, g);
			    
			    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
			    keyPairGenerator.initialize(512);
			    KeyPair keyPair = keyPairGenerator.generateKeyPair();
			    PrivateKey privateKey  = keyPair.getPrivate();
			    PublicKey publicKey = keyPair.getPublic();
			    
			    System.out.println("sending my public key: " + publicKey);
			    out.writeObject(publicKey);
	            out.flush();
	            PublicKey serverPublickey = (PublicKey)in.readObject();
	    	    System.out.println("got public key: " + serverPublickey);
	    	    
	    	    KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
	    	    keyAgreement.init(privateKey);
	    	    keyAgreement.doPhase(serverPublickey, true);
	    	    byte[] secretKey = new byte[16];
	    	    System.arraycopy(keyAgreement.generateSecret(), 0, secretKey, 0, secretKey.length);
	    	    
	    	    //************************************************************************

	    	    int paddingNeeded = test.length()%4;
	    	    for (int i = 0; i < paddingNeeded; i++) {
	    	    	test = test + "\0";
	    	    }
	    	    
	    	    byte[] messagebyte = test.getBytes("UTF-8");
	    	    System.out.println("message as bytes: " + messagebyte + " with size: " + messagebyte.length);
	    	    
	    	    
	    	    
	    	    IntBuffer intBuf =
	    	    		   ByteBuffer.wrap(messagebyte)
	    	    		     .order(ByteOrder.BIG_ENDIAN)
	    	    		     .asIntBuffer();
	    	    		 int[] v = new int[intBuf.remaining()];
	    	    		 intBuf.get(v);
	    	    		 
//	    	    int vpaddingNeeded = v.length%2;
//	    	    for (int i = 0; i < vpaddingNeeded; i++) {
//	    	    	int[] oldv = v;
//	    	    	v = new int[oldv.length + 1];
//	    	    	int[] arrayPad = new int[1];
//	    	    	arrayPad[0] = 0;
//	    	    	System.arraycopy(oldv, 0, v, 0, oldv.length);
//	    	    	System.arraycopy(arrayPad, 0, v, oldv.length, arrayPad.length);
//	    	    }
	    	    		 
//	    	    ByteBuffer byteBuf = ByteBuffer.allocate((v.length)*4);
//	    	    intBuf = byteBuf.asIntBuffer();
//	    	    intBuf.put(v);
//	    	    
//	    	    byte[] messagebyte2 = byteBuf.array();
//	    	    
//	    	    String test2 = new String(messagebyte2, "UTF-8");
//	    	    System.out.println("trying to get string back: " + test2); 
	    	    
	    	    System.out.println("message as int[]: " + Arrays.toString(v));
	    	    
	    	    System.out.println("key as a byte[]: " + secretKey + "with size: " + secretKey.length);
	    	    
	    	    intBuf =
	    	    		   ByteBuffer.wrap(secretKey)
	    	    		     .order(ByteOrder.BIG_ENDIAN)
	    	    		     .asIntBuffer();
	    	    		 int[] k = new int[intBuf.remaining()];
	    	    		 intBuf.get(k);
	    	        
	    	    System.out.println("key as int[]: " + Arrays.toString(k));
	    	    
	    	    for (int i = 0; i<v.length-1; i+=2) {
//	    	    	int[] encryptedv = new int[2];
//	    	    	encryptedv[0] = v[i];
//	    	    	encryptedv[1] = v[i+1];
	    	    	encrypter.encrypt(v, k);
//	    	    	System.out.println("encryptedv after encrypt: " + Arrays.toString(encryptedv));
//	    	    	v[i] = encryptedv[0];
//	    	    	v[i+1] = encryptedv[1];
	    	    }
//	    	    encrypter.encrypt(v, k);
	    	    
	    	    System.out.println("v after it was encrypted: " + Arrays.toString(v));
	    	    //************************************************************************

	    	    
//	    	    System.out.println("sending my encrypted message ");
//			    out.writeObject(v);
//	            out.flush();
	    	    
	    	    
	    	    //************************************************************************
	    	    
	    	    for (int i = 0; i<v.length-1; i+=2) {
	    	    	int[] decryptedv = new int[2];
	    	    	decryptedv[0] = v[i];
	    	    	System.out.println("decrypting v0: " + decryptedv[0]);
	    	    	decryptedv[1] = v[i+1];
	    	    	System.out.println("decrypting v1: " + decryptedv[1]);
	    	    	System.out.println("the key being used for decryption: " + Arrays.toString(k));
	    	    	decrypter.decrypt(decryptedv, k);
	    	    	v[i] = decryptedv[0];
	    	    	v[i+1] = decryptedv[1];
	    	    }
	    	    
	    	    System.out.println("v after it was decrypted: " + Arrays.toString(v));
	    	    
	    	    ByteBuffer byteBuf = ByteBuffer.allocate((v.length)*4);
	    	    intBuf = byteBuf.asIntBuffer();
	    	    intBuf.put(v);
	    	    
	    	    byte[] messagebyte2 = byteBuf.array();
	    	    
	    	    String test2 = new String(messagebyte2, "UTF-8");
	    	    System.out.println("trying to get string back with decryption: " + test2);
	    	    
	    	    //***************************************************************************
	    	    
	    	    
//			    PublicKey serverPublicKey = 
			    
//			    KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
//			    KeyPair aPair = keyPairGenerator.generateKeyPair();
//			    KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");
//			    KeyPair bPair = keyPairGenerator.generateKeyPair();
//			    
//			    aKeyAgree.init(aPair.getPrivate());
//			    bKeyAgree.init(bPair.getPrivate());
//			    
//			    aKeyAgree.doPhase(bPair.getPublic(), true);
//			    bKeyAgree.doPhase(aPair.getPublic(), true);
//
//			    MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
//			    System.out.println("aKeyAgree: " + new String(hash.digest(aKeyAgree.generateSecret())));
//			    System.out.println("bKeyAgree: " + new String(hash.digest(bKeyAgree.generateSecret())));
			    
//			    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//			    keyGenerator.init(128);
//			    Key key = keyGenerator.generateKey();
//			    System.out.println(key.toString());
//			    
//			    Encoder encoder = Base64.getEncoder();
//			    test = encoder.encode(test);
//			    System.out.println("string as 64 bit: " + test.getBytes("UTF-8"));
//			    byte[]   bytesEncoded = Base64.encodeBase64(test.getBytes());
//			    System.out.println("encoded value is " + test.getBytes());
			    
//			    int[] v = new int[test.length()];
//			    for (int i = 0; i <test.length(); i++ ) {
//			    	char c = test.charAt(i);
//			    	int character = c - 'a' +1;
//			    	v[i] = character;
//			    }
			    
//			    System.out.println("string as int[]: " + Arrays.toString(v));
			    
//			    System.out.println("my key as byte[] is: " + Arrays.toString(key));
			    
//			    int[] intKey = new int[key.getEncoded().length];
//			    for(int i =0; i < key.getEncoded().length; i++) {
//			    	intKey[i] = key.getEncoded()[i] & 0xff;
//			    }
			    
//			    System.out.println("my key as int[] is: " + Arrays.toString(intKey));
//			    
//			    encrypter.encrypt(v, intKey);
//			    
//			    System.out.println("v after encryption: " + Arrays.toString(v));
//			    
//			    KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
			    
			    String message = null;
			    
			    sendMessage("Connection successful");
//                System.out.println("sent message");
                

			    do{
//                    System.out.println("sent message");

	                try{
//	                    System.out.println("sent message");

	                    message = (String)in.readObject();
	                    System.out.println("server>" + message);
	                    sendMessage("Hi my server");
	                    message = "bye";
	                    sendMessage(message);
	                    System.out.println("sent message");
	                }
	                catch(ClassNotFoundException classNot){
	                    System.err.println("data received in unknown format");
	                }
	            }while(!message.equals("bye"));
			    
			    
			    
		}catch (IOException e) {
		  	    System.out.println("Could not listen on port 16000");
		  	    System.exit(-1);
		  	  
		        
		}
        finally{
            //4: Closing connection
            try{
                in.close();
                out.close();
                socket.close();
            }
            catch(IOException ioException){
                ioException.printStackTrace();
            }
        }
    }
    
    static void sendMessage(String msg)
    {
        try{
            out.writeObject(msg);
            out.flush();
            System.out.println("client>" + msg);
        }
        catch(IOException ioException){
            ioException.printStackTrace();
        }
    }
}
