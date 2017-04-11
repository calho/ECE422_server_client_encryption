import java.io.BufferedReader;
import java.io.File;
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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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
	static String username;
	
	public static int[] encryptString(String string, int[] k) throws UnsupportedEncodingException{
		int paddingNeeded = (8-string.length()%8);
//	    System.out.println("test length: " + string.length() + " padding needed: " + paddingNeeded);
	    for (int i = 0; i < paddingNeeded; i++) {
	    	string = string + "\0";
	    }
	    
	    byte[] messagebyte = string.getBytes("UTF-8");
//	    System.out.println("message as bytes: " + messagebyte + " with size: " + messagebyte.length);
	    
	    IntBuffer intBuf =
	    		   ByteBuffer.wrap(messagebyte)
	    		     .order(ByteOrder.BIG_ENDIAN)
	    		     .asIntBuffer();
	    		 int[] v = new int[intBuf.remaining()];
	    		 intBuf.get(v);
	    		 
//	    System.out.println("message as int[]: " + Arrays.toString(v));

	    int[] vcopy = new int[v.length];
		 for (int i = 0; i<v.length-1; i+=2) {
    	    	int[] encryptedv = new int[2];
    	    	encryptedv[0] = v[i];
    	    	encryptedv[1] = v[i+1];
    	    	encrypter.encrypt(encryptedv, k);
//    	    	System.out.println("encryptedv after encrypt: " + Arrays.toString(encryptedv));
    	    	vcopy[i] = encryptedv[0];
    	    	vcopy[i+1] = encryptedv[1];
    	    }
		 return vcopy;
	}
	
	public static String decryptintarr(int[] v, int[] k) throws UnsupportedEncodingException {
		int[] vcopy = new int[v.length];
		for (int i = 0; i<v.length-1; i+=2) {
	    	int[] decryptedv = new int[2];
	    	decryptedv[0] = v[i];
	    	decryptedv[1] = v[i+1];
	    	decrypter.decrypt(decryptedv, k);
	    	vcopy[i] = decryptedv[0];
	    	vcopy[i+1] = decryptedv[1];
	    }
		
		ByteBuffer byteBuf = ByteBuffer.allocate((vcopy.length)*4);
	    IntBuffer intBuf = byteBuf.asIntBuffer();
	    intBuf.put(vcopy);
	    
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
//			    System.out.println("connected on client side");
			    			    
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
	    	    IntBuffer intBuf =
	    	    		   ByteBuffer.wrap(secretKey)
	    	    		     .order(ByteOrder.BIG_ENDIAN)
	    	    		     .asIntBuffer();
	    	    		 int[] k = new int[intBuf.remaining()];
	    	    		 intBuf.get(k);
	    	    		 
	    	    boolean loggingin = true;
	    	    while (loggingin) {
		    	    Scanner reader = new Scanner(System.in);  
		    	    System.out.print("Username: ");
		    	    username = reader.nextLine();
		    	    
	//	    	    reader = new Scanner(System.in);  
		    	    System.out.print("Password: ");
		    	    String password = reader.nextLine();
	
		    	    
	//	    	    System.out.println("key as a byte[]: " + secretKey + "with size: " + secretKey.length);
		    	    
	
		    	        
	//	    	    System.out.println("key as int[]: " + Arrays.toString(k));
		    	    
		    	    
		    	    int[] intusername = encryptString(username, k);
		    	    int[] intpassword = encryptString(password, k);
		    	    
		    	    sendMessage(intusername);
		    	    sendMessage(intpassword);

	                int[] ack = (int[])in.readObject();

	                String ackDecrypted = decryptintarr(ack, k).trim();
	                
//	                System.out.println("ack recieved was: " + ackDecrypted);
	                
	                boolean ackBoolean = true;
	                if (ackDecrypted.equals("ERROR")){
		                	System.out.print("invalid login. Would you like to try again? (y/n), n will close connection ");
		                	String ackResponse = reader.nextLine();
		                    while(ackBoolean) {
	
			                	if (ackResponse.equals("y")) {
			                		sendMessage(encryptString("again", k));
			                		ackBoolean = false;
			                	}
			                	else if (ackResponse.equals("n")) {
			                		sendMessage(encryptString("finished", k));
			            
			                		try{
			                            in.close();
			                            out.close();
			                            socket.close();
			                            System.out.println("bye");
			                            System.exit(1);
			                        }
			                        catch(IOException ioException){
			                            ioException.printStackTrace();
			                        }
			                	}
			                	else {
			                		System.out.print("invalid response. Would you like to try logging in again? (y/n) ");
				                	ackResponse = reader.nextLine();
			                	}
		                    }
	                }
	                else if(ackDecrypted.equals("ACK")) {
	                	System.out.println("log in successful");
	    	    	    sendMessage(encryptString("filename", k));
	    	    	    
	    	    	    File clientFolder = new File(username);
	    	    	    if (!clientFolder.exists()) {
//	    	    	        System.out.println("creating directory: " + theDir.getName());
	    	    	        boolean result = false;

	    	    	        try{
	    	    	            clientFolder.mkdir();
	    	    	            result = true;
	    	    	        } 
	    	    	        catch(SecurityException se){
	    	    	            System.out.println("permission preventing client folder from being created");
	    	    	        }        
	    	    	        if(result) {    
//	    	    	            System.out.println("DIR created");  
	    	    	        }
	    	    	    }
	                	loggingin = false;
	                }
	    	    }
	    	    
	    	    
	    	    
	    	    boolean gettingFile = true;
                while (gettingFile){
		    	    Scanner reader = new Scanner(System.in);
	                System.out.print("Filename: ");
		    	    String filename = reader.nextLine();
		    	    
		    	    int[] intfilename = encryptString(filename, k);
		    	    sendMessage(intfilename);
		    	    
		    	    String fileContent = null;
		    	    
		    	    int[] fileContentint = (int[])in.readObject();
	                fileContent = decryptintarr(fileContentint, k).trim();
//	                System.out.println("recieved file content: " + fileContent);
	                
	                String keepSearching = "y";
	                
	                if (fileContent.equals("file not found")){
	                	System.out.print("file was not found. would you like to try again? (y/n) n will close connection: ");
	                	keepSearching = reader.nextLine();
	                	boolean searchResponse = true;
		                while (searchResponse) {
			                if (keepSearching.equals("n")) {
			                	sendMessage(encryptString("finished", k));
			                	try{
		                            in.close();
		                            out.close();
		                            socket.close();
		                            System.out.println("bye");
		                            System.exit(1);
		                        }
		                        catch(IOException ioException){
		                            ioException.printStackTrace();
		                        }			                }
			                else if (keepSearching.equals("y")) {
			                	sendMessage(encryptString("again", k));
			                	searchResponse = false;
			                }
			                else if(!keepSearching.equals("y")) {
			                	System.out.print("invalid input. would you like to search file again? (y/n): ");
			                	keepSearching = reader.nextLine();
			                }
		                }
	                }
	                else if (!fileContent.equals("file not found")){
	                	String storedFile = "./"+username+"/"+filename;
	                	if (Files.exists(Paths.get(storedFile))){
				    		try {
			//	    			System.out.println("appending to file");
				      		    Files.write(Paths.get(storedFile), fileContent.getBytes(), StandardOpenOption.TRUNCATE_EXISTING);
				      		}catch (IOException e) {
				      		    System.out.println("failed to write to file to store");
				      		}
				    	}
				    	else {
				    		try {
			//	    			System.out.println("creating file");
				      		    Files.write(Paths.get(storedFile), fileContent.getBytes());
				      		}catch (IOException e) {
				      		    System.out.println("failed to write to file to store");
				      		}
				    	}
	                	
	                	System.out.print("file was found. content stored in your file. would you like to search again? (y/n) n will close connection: ");
	                	keepSearching = reader.nextLine();
	                	boolean searchResponse = true;
		                while (searchResponse) {
			                if (keepSearching.equals("n")) {
			                	sendMessage(encryptString("finished", k));
			                	try{
		                            in.close();
		                            out.close();
		                            socket.close();
		                            System.out.println("bye");
		                            System.exit(1);
		                        }
		                        catch(IOException ioException){
		                            ioException.printStackTrace();
		                        }
//			                	gettingFile =false;
			                }
			                else if (keepSearching.equals("y")) {
			                	sendMessage(encryptString("again", k));
			                	searchResponse = false;
			                }
			                else if(!keepSearching.equals("y")) {
			                	System.out.print("invalid input. would you like to search file again? (y/n): ");
			                	keepSearching = reader.nextLine();
			                }
		                }
	                }
	                     
                }
		}
	    	 			    
//			    String message = null;
//			    
//			    sendMessage("Connection successful");
////                System.out.println("sent message");
//                
//
//			    do{
////                    System.out.println("sent message");
//
//	                try{
////	                    System.out.println("sent message");
//
//	                    message = (String)in.readObject();
//	                    System.out.println("server>" + message);
//	                    sendMessage("Hi my server");
//	                    message = "bye";
//	                    sendMessage(message);
//	                    System.out.println("sent message");
//	                }
//	                catch(ClassNotFoundException classNot){
//	                    System.err.println("data received in unknown format");
//	                }
//	            }while(!message.equals("bye"));
//			    
//			    
//			    
		catch (IOException e) {
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
//            System.out.println("client>" + msg);
        }
        catch(IOException ioException){
            ioException.printStackTrace();
        }
    }
}
