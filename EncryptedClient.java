import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
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
import java.util.Scanner;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;




public class EncryptedClient {
	static Socket socket;
	static ObjectOutputStream out;
	static ObjectInputStream in;
	static MyEncrypt encrypter = new MyEncrypt();
	static MyDecrypt decrypter = new MyDecrypt();
	
	public static int[] encryptString(String string, int[] k) throws UnsupportedEncodingException{
		int paddingNeeded = (8-string.length()%8);
	    System.out.println("test length: " + string.length() + " padding needed: " + paddingNeeded);
	    for (int i = 0; i < paddingNeeded; i++) {
	    	string = string + "\0";
	    }
	    
	    byte[] messagebyte = string.getBytes("UTF-8");
	    System.out.println("message as bytes: " + messagebyte + " with size: " + messagebyte.length);
	    
	    IntBuffer intBuf =
	    		   ByteBuffer.wrap(messagebyte)
	    		     .order(ByteOrder.BIG_ENDIAN)
	    		     .asIntBuffer();
	    		 int[] v = new int[intBuf.remaining()];
	    		 intBuf.get(v);
	    		 
	    System.out.println("message as int[]: " + Arrays.toString(v));

	    		 
		 for (int i = 0; i<v.length-1; i+=2) {
    	    	int[] encryptedv = new int[2];
    	    	encryptedv[0] = v[i];
    	    	encryptedv[1] = v[i+1];
    	    	encrypter.encrypt(encryptedv, k);
    	    	System.out.println("encryptedv after encrypt: " + Arrays.toString(encryptedv));
    	    	v[i] = encryptedv[0];
    	    	v[i+1] = encryptedv[1];
    	    }
		 return v;
	}
	
	public static String decryptintarr(int[] v, int[] k) throws UnsupportedEncodingException {
		for (int i = 0; i<v.length-1; i+=2) {
	    	int[] decryptedv = new int[2];
	    	decryptedv[0] = v[i];
	    	decryptedv[1] = v[i+1];
	    	decrypter.decrypt(decryptedv, k);
	    	v[i] = decryptedv[0];
	    	v[i+1] = decryptedv[1];
	    }
		
		ByteBuffer byteBuf = ByteBuffer.allocate((v.length)*4);
	    IntBuffer intBuf = byteBuf.asIntBuffer();
	    intBuf.put(v);
	    
	    byte[] messagebyte = byteBuf.array();
	    
	    String string = new String(messagebyte, "UTF-8");
	    
	    return string;
	}
	
    @SuppressWarnings("resource")
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, ClassNotFoundException {

    	System.loadLibrary("encrypt");
    	System.loadLibrary("decrypt");
    	
//    	String test = "Hello World!";
    	
    	
    	
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
			    
//			    System.out.println("sending my public key: " + publicKey);
			    out.writeObject(publicKey);
	            out.flush();
	            PublicKey serverPublickey = (PublicKey)in.readObject();
//	    	    System.out.println("got public key: " + serverPublickey);
	    	    
	    	    KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
	    	    keyAgreement.init(privateKey);
	    	    keyAgreement.doPhase(serverPublickey, true);
	    	    byte[] secretKey = new byte[16];
	    	    System.arraycopy(keyAgreement.generateSecret(), 0, secretKey, 0, secretKey.length);
	    	    
	    	    //************************************************************************
	    	    
	    	    Scanner reader = new Scanner(System.in);  
	    	    System.out.print("Username: ");
	    	    String username = reader.nextLine();
	    	    
//	    	    reader = new Scanner(System.in);  
	    	    System.out.print("Password: ");
	    	    String password = reader.nextLine();

//	    	    int paddingNeeded = (8-test.length()%8);
//	    	    System.out.println("test length: " + test.length() + " padding needed: " + paddingNeeded);
//	    	    for (int i = 0; i < paddingNeeded; i++) {
//	    	    	test = test + "\0";
//	    	    }
//	    	    
//	    	    byte[] messagebyte = test.getBytes("UTF-8");
//	    	    System.out.println("message as bytes: " + messagebyte + " with size: " + messagebyte.length);
//	    	    
//	    	    IntBuffer intBuf =
//	    	    		   ByteBuffer.wrap(messagebyte)
//	    	    		     .order(ByteOrder.BIG_ENDIAN)
//	    	    		     .asIntBuffer();
//	    	    		 int[] v = new int[intBuf.remaining()];
//	    	    		 intBuf.get(v);
//	    	    		    	    
//	    	    System.out.println("message as int[]: " + Arrays.toString(v));
	    	    
	    	    System.out.println("key as a byte[]: " + secretKey + "with size: " + secretKey.length);
	    	    
	    	    IntBuffer intBuf =
	    	    		   ByteBuffer.wrap(secretKey)
	    	    		     .order(ByteOrder.BIG_ENDIAN)
	    	    		     .asIntBuffer();
	    	    		 int[] k = new int[intBuf.remaining()];
	    	    		 intBuf.get(k);
	    	        
	    	    System.out.println("key as int[]: " + Arrays.toString(k));
	    	    
//	    	    for (int i = 0; i<v.length-1; i+=2) {
//	    	    	int[] encryptedv = new int[2];
//	    	    	encryptedv[0] = v[i];
//	    	    	encryptedv[1] = v[i+1];
//	    	    	encrypter.encrypt(encryptedv, k);
//	    	    	System.out.println("encryptedv after encrypt: " + Arrays.toString(encryptedv));
//	    	    	v[i] = encryptedv[0];
//	    	    	v[i+1] = encryptedv[1];
//	    	    }
	    	    
	    	    int[] intusername = encryptString(username, k);
	    	    int[] intpassword = encryptString(password, k);
	    	    
	    	    sendMessage(intusername);
	    	    sendMessage(intpassword);
	    	    
                int[] ack = (int[])in.readObject();
                String ackDecrypted = decryptintarr(ack, k).trim();
                
                System.out.println("ack recieved was: " + ackDecrypted);
                
                System.out.print("Filename: ");
	    	    String filename = reader.nextLine();
	    	    
	    	    int[] intfilename = encryptString(filename, k);
	    	    sendMessage(intfilename);
	    	    
	    	    String fileContent = null;
	    	    
	    	    int[] fileContentint = (int[])in.readObject();
                fileContent = decryptintarr(fileContentint, k).trim();
                System.out.println("recieved file content: " + fileContent);
                
//	    	    do{
//
//	                try{
//	                	System.out.println("trying to read");
//	                	int[] fileContentint = (int[])in.readObject();
//	                    fileContent = decryptintarr(fileContentint, k).trim();
//	                    if (fileContent.equals("file not found")) {
//	                    	throw new Exception();
//	                    }
//	                    System.out.println("recieved file content: " + fileContent);
//	                }
//	                catch(Exception e){
//	                    System.err.println("file was not found");
//	                    break;
//	                }
//	            }while(!fileContent.equals("END") || !fileContent.equals("file not found"));

	    	    
//	    	    System.out.println("v after it was encrypted: " + Arrays.toString(v));
	    	    //************************************************************************

	    	    
//	    	    System.out.println("sending my encrypted message ");
//			    out.writeObject(v);
//	            out.flush();
	    	    
	    	    
	    	    //************************************************************************
	    	    
//	    	    for (int i = 0; i<v.length-1; i+=2) {
//	    	    	int[] decryptedv = new int[2];
//	    	    	decryptedv[0] = v[i];
//	    	    	System.out.println("decrypting v0: " + decryptedv[0]);
//	    	    	decryptedv[1] = v[i+1];
//	    	    	System.out.println("decrypting v1: " + decryptedv[1]);
//	    	    	System.out.println("the key being used for decryption: " + Arrays.toString(k));
//	    	    	decrypter.decrypt(decryptedv, k);
//	    	    	v[i] = decryptedv[0];
//	    	    	v[i+1] = decryptedv[1];
//	    	    }
//	    	    
////	    	    if (vpaddingNeeded == 1) {
////	    	    	v[v.length-1] = 0;
////	    	    }
//	    	    
//	    	    System.out.println("v after it was decrypted: " + Arrays.toString(v));
//	    	    
//	    	    ByteBuffer byteBuf = ByteBuffer.allocate((v.length)*4);
//	    	    intBuf = byteBuf.asIntBuffer();
//	    	    intBuf.put(v);
//	    	    
//	    	    byte[] messagebyte2 = byteBuf.array();
//	    	    
//	    	    String test2 = new String(messagebyte2, "UTF-8");
//	    	    System.out.println("trying to get string back with decryption: " + test2);
	    	    
	    	    //***************************************************************************
	    	 			    
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
    
    static void sendMessage(Object msg)
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
