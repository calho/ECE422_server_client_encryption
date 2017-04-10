import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

public class EncryptedServer {
	static Socket clientSocket;
	static ServerSocket serverSocket;
	static ObjectOutputStream out;
	static ObjectInputStream in;
	
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException {
    	
    	MyEncrypt encrypter = new MyEncrypt();
    	System.loadLibrary("encrypt");
    	MyDecrypt decrypter = new MyDecrypt();
    	System.loadLibrary("decrypt");
    	
    	String test = "Hello World";
    	
  	  try{
  	    serverSocket = new ServerSocket(16000); 
  	    clientSocket = serverSocket.accept();
  	    
  	    out = new ObjectOutputStream(clientSocket.getOutputStream());
	    in = new ObjectInputStream(clientSocket.getInputStream());
	    
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
	    keyPairGenerator.initialize(512);
	    KeyPair keyPair = keyPairGenerator.generateKeyPair();
	    PrivateKey privateKey  = keyPair.getPrivate();
	    PublicKey publicKey = keyPair.getPublic();
	    
	    PublicKey clientPublickey = (PublicKey)in.readObject();
	    System.out.println("got public key: " + clientPublickey);
	    System.out.println("sending my public key: " + publicKey);
	    out.writeObject(publicKey);
        out.flush();
        
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
	    keyAgreement.init(privateKey);
	    keyAgreement.doPhase(clientPublickey, true);
	    byte[] secretKey = new byte[16];
	    System.arraycopy(keyAgreement.generateSecret(), 0, secretKey, 0, secretKey.length);
	    
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
	    		 
	    
	    		 
//	    int vpaddingNeeded = v.length%2;
//	    for (int i = 0; i < vpaddingNeeded; i++) {
//	    	int[] oldv = v;
//	    	v = new int[oldv.length + 1];
//	    	int[] arrayPad = new int[1];
//	    	arrayPad[0] = 0;
//	    	System.arraycopy(oldv, 0, v, 0, oldv.length);
//	    	System.arraycopy(arrayPad, 0, v, oldv.length, arrayPad.length);
//	    }
	    		 
//	    ByteBuffer byteBuf = ByteBuffer.allocate((v.length)*4);
//	    intBuf = byteBuf.asIntBuffer();
//	    intBuf.put(v);
//	    
//	    byte[] messagebyte2 = byteBuf.array();
//	    
//	    String test2 = new String(messagebyte2, "UTF-8");
//	    System.out.println("trying to get string back: " + test2); 
	    
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
	    	int[] encryptedv = new int[2];
	    	encryptedv[0] = v[i];
	    	encryptedv[1] = v[i+1];
	    	encrypter.encrypt(encryptedv, k);
	    	v[i] = encryptedv[0];
	    	v[i+1] = encryptedv[1];
	    }
//	    encrypter.encrypt(v, k);
	    
	    System.out.println("v after it was encrypted: " + Arrays.toString(v));
	    
	    System.out.println("key as a byte[]: " + secretKey + "with size: " + secretKey.length);
	    
//	     intBuf =
//	    		   ByteBuffer.wrap(secretKey)
//	    		     .order(ByteOrder.BIG_ENDIAN)
//	    		     .asIntBuffer();
//	    		 int[] k = new int[intBuf.remaining()];
//	    		 intBuf.get(k);
//	        
//	    System.out.println("key as int[]: " + Arrays.toString(k));
	    
//	    int[] v = (int[])in.readObject();
//	    System.out.println("got encrypted message: " + Arrays.toString(v));
	    
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
  	    
//	    out.println("server: hi there");
	      	    
  	    System.out.println("conencted on server side");
  	    
  	   String message = null; 
  	 sendMessage("Connection successful");
  	   
	  	do{
	       try{
	           message = (String)in.readObject();
	           System.out.println("client>" + message);
	           if (message.equals("bye"))
	        	   try{
	                   out.writeObject("bye");
	                   out.flush();
	                   System.out.println("server>" + "bye");
	               }
	               catch(IOException ioException){
	                   ioException.printStackTrace();
	               }
	        
	       }
	       catch(ClassNotFoundException classnot){
	           System.err.println("Data received in unknown format");
	       }
	   }while(!message.equals("bye"));
  	  
  	  } catch (IOException e) {
  	    System.out.println("Could not listen on port 16000");
  	    System.exit(-1);
  	  
        
  	  }
      finally{
          //4: Closing connection
          try{
              in.close();
              out.close();
              serverSocket.close();
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
            System.out.println("server>" + msg);
        }
        catch(IOException ioException){
            ioException.printStackTrace();
        }
    }
    
}
