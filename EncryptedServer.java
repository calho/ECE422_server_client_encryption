import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import javax.crypto.KeyAgreement;

public class EncryptedServer {
	static Socket clientSocket;
	static ServerSocket serverSocket;
//	static ObjectOutputStream out;
//	static ObjectInputStream in;
	static MyEncrypt encrypter = new MyEncrypt();
	static MyDecrypt decrypter = new MyDecrypt();
	static ConcurrentHashMap<String,List<Object>> shadowTable = new ConcurrentHashMap<String, List<Object>>();
	boolean mainServerRunning = true;
	
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
	
	public EncryptedServer() {
		try {
	  	    serverSocket = new ServerSocket(16000); 
	  	    
		}catch(IOException e) {
			 System.out.println("Could not listen on port 16000");
		  	 System.exit(-1);
		}
		
		while (mainServerRunning) {
			try {
				System.out.println("waiting for client connection");
		  	    clientSocket = serverSocket.accept();
		  	    System.out.println("socket connected to a client");
		  	    ClientServerThread clientServiceThread = new ClientServerThread(clientSocket);
		  	    clientServiceThread.start();
			}catch(IOException e) {
				System.out.println("failed to create thread for client");
		        e.printStackTrace();
			}
		}
		try {
			serverSocket.close();
			System.out.println("server stopped");
		} catch(Exception e) {
			System.out.println("failed in closing server socket");
		  	 System.exit(-1);
		}
	}
	
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException {
    	
    	System.loadLibrary("encrypt");
    	System.loadLibrary("decrypt");
    	
  		  
  		
  		String hashKeyString = "2fc14f685474c6ca";
    	byte[] hashKeyByte = hashKeyString.getBytes();
//    	System.out.println("hashkey as a byte[]: " + hashKeyByte + "with size: " + hashKeyByte.length);
    	
		IntBuffer intBuf =
		    		   ByteBuffer.wrap(hashKeyByte)
		    		     .order(ByteOrder.BIG_ENDIAN)
		    		     .asIntBuffer();
		    		 int[] hashk = new int[intBuf.remaining()];
		    		 intBuf.get(hashk);
  		  
    	Scanner reader = new Scanner(System.in);  
	    System.out.print("would you like to add users? (y/n):  ");
	    String addUsers = reader.nextLine();
	    
	    boolean addUsersBoolean = true;
	    while (addUsersBoolean) {
		    if (addUsers.equals("y")) {
		    	while (addUsers.equals("y")){
			    	System.out.print("Username: ");
				    String username = reader.nextLine();
				    System.out.print("Password: ");
				    String password = reader.nextLine();
				    
				    Random random  = new SecureRandom();
			    	byte[] saltByte = new byte[16];
			    	random.nextBytes(saltByte);
			    	String saltString = saltByte.toString();
			    	
			    	String stringHash = password + saltString;
		//	    	System.out.println("hashing " + password + " with " + saltString + " to get " + stringHash);
			    	
			    	   	    	
			    	int[] hashint = encryptString(stringHash, hashk);
			    	
			    	if (Files.exists(Paths.get("./shadowFile.txt"))){
			    		try {
		//	    			System.out.println("appending to file");
			      		    Files.write(Paths.get("shadowFile.txt"), (username+">"+saltString+">"+Arrays.toString(hashint)+"\n").getBytes(), StandardOpenOption.APPEND);
			      		}catch (IOException e) {
			      		    System.out.println("failed to write to shadow file");
			      		}
			    	}
			    	else {
			    		try {
		//	    			System.out.println("creating file");
			      		    Files.write(Paths.get("shadowFile.txt"), (username+">"+saltString+">"+Arrays.toString(hashint)+"\n").getBytes());
			      		}catch (IOException e) {
			      		    System.out.println("failed to write to shadow file");
			      		}
			    	}
			    	System.out.print("Keep adding? (y/n): ");
			    	addUsers = reader.nextLine();
		    	}
		    }
		    else if (!addUsers.equals("n")) {
		    	System.out.print("invalid response. would you like to add users? (y/n): ");
		    	addUsers = reader.nextLine();
		    }
		    else {
		    	if (!Files.exists(Paths.get("./shadowFile.txt"))){
		    		File f = new File("./shadowFile.txt");

		    		f.getParentFile().mkdirs(); 
		    		f.createNewFile();
		    	}
		    	addUsersBoolean = false;
		    }
	    }
	    
	    try {
		    String path = "./shadowFile.txt";
//		    System.out.println("trying to read shadowFile");
		    FileInputStream fileInputStream = new FileInputStream(path);
		    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(fileInputStream));
		    String line;
		    while((line = bufferedReader.readLine()) != null) {
		    	String[] shadowValues = line.split(">");
		    	
		    	String shadowUsername = shadowValues[0];
		    	String shadowSalt = shadowValues[1];
		    	String shadowHash = shadowValues[2];
		    	String[] shadowHasharr = shadowHash.replaceAll("\\[", "").replaceAll("\\]", "").replaceAll("\\s", "").split(",");

		    	int[] hash = new int[shadowHasharr.length];

		    	for (int i = 0; i < shadowHasharr.length; i++) {
		    	    try {
		    	        hash[i] = Integer.parseInt(shadowHasharr[i]);
		    	    } catch (NumberFormatException nfe) {
		    	    };
		    	}
		    	List<Object> Salt = new ArrayList<Object>();
		    	Salt.add(shadowSalt);
//		    	System.out.println("obtained shadow salt: " + shadowSalt);
		    	Salt.add(hash);
//		    	System.out.println("obtained shadow hash: " + Arrays.toString(hash));
//		    	System.out.println("obtained shadow username: " + shadowUsername);

//		    	System.out.println("salt value is: " + demoSalt.get(0));
		    	shadowTable.put(shadowUsername, Salt);
		    	
//		    	System.out.println(line);
		    }
	    }

	    catch (Exception e) {
	    	System.out.println("file not found error");
	    }
  	  
	    new EncryptedServer();
	    
    }
	      	    
    

    
    class ClientServerThread extends Thread {
    	Socket clientServerSocket;
    	boolean threadRunning = true;
    	ObjectOutputStream out;
		ObjectInputStream in;
		
    	public ClientServerThread(Socket s){
    		clientServerSocket = s;
    	}
    	
    	public void run() {
    		System.loadLibrary("encrypt");
        	System.loadLibrary("decrypt");
        	
    		String hashKeyString = "2fc14f685474c6ca";
        	byte[] hashKeyByte = hashKeyString.getBytes();
//        	System.out.println("hashkey as a byte[]: " + hashKeyByte + "with size: " + hashKeyByte.length);
        	
    		IntBuffer intBuf =
    		    		   ByteBuffer.wrap(hashKeyByte)
    		    		     .order(ByteOrder.BIG_ENDIAN)
    		    		     .asIntBuffer();
    		    		 int[] hashk = new int[intBuf.remaining()];
    		    		 intBuf.get(hashk);

    		System.out.println("Server thread connected to client");
    		try {
    			out = new ObjectOutputStream(clientSocket.getOutputStream());
    			in = new ObjectInputStream(clientSocket.getInputStream());
    			
    			while (threadRunning) {
    				
    				if (!mainServerRunning) {
    					System.out.println("main server has stopped");
    					threadRunning = false;
    				} 
    				
    				
	    			String finished = null;
	    		    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
	    		    keyPairGenerator.initialize(512);
	    		    KeyPair keyPair = keyPairGenerator.generateKeyPair();
	    		    PrivateKey privateKey  = keyPair.getPrivate();
	    		    PublicKey publicKey = keyPair.getPublic();
	    		    
	    		    PublicKey clientPublickey = (PublicKey)in.readObject();
	//    		    System.out.println("got public key: " + clientPublickey);
	//    		    System.out.println("sending my public key: " + publicKey);
	    		    out.writeObject(publicKey);
	    	        out.flush();
	    	        
	    	        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
	    		    keyAgreement.init(privateKey);
	    		    keyAgreement.doPhase(clientPublickey, true);
	    		    byte[] secretKey = new byte[16];
	    		    System.arraycopy(keyAgreement.generateSecret(), 0, secretKey, 0, secretKey.length);
	    		    
	//    		    System.out.println("key as a byte[]: " + secretKey + "with size: " + secretKey.length);
	    		    
	    		    intBuf =
	    		    		   ByteBuffer.wrap(secretKey)
	    		    		     .order(ByteOrder.BIG_ENDIAN)
	    		    		     .asIntBuffer();
	    		    		 int[] k = new int[intBuf.remaining()];
	    		    		 intBuf.get(k);
	    		        
	//    		    System.out.println("key as int[]: " + Arrays.toString(k));
	    		    
	//    		    System.out.println("v after it was encrypted: " + Arrays.toString(v));
	    		    
	//    		    System.out.println("key as a byte[]: " + secretKey + "with size: " + secretKey.length);
	    		    
	    		    		 
	    		    boolean loggingin = true;
	    		    while (loggingin) {
	    		        int[] usernameint = (int[])in.readObject();
	    		        int[] passwordint = (int[])in.readObject();
	    		        
	    		        String username = decryptintarr(usernameint, k).trim();
	    		        String password = decryptintarr(passwordint, k).trim();
	    		        
	//    			    System.out.println("username: " + username);
	//    			    System.out.println("password: " + password);
	    		  	    
	    			    try {
//	    			    	System.out.println("searching for user " + username);
	    				    List<Object> saltValues = shadowTable.get(username);

	    				    String salt = (String) saltValues.get(0);
	    				    int[] hashValue = (int[]) saltValues.get(1);
//	    				    System.out.println(Arrays.toString(hashValue));
	    				    String hashedString = decryptintarr(hashValue, hashk);
	    				    String foundPassword = hashedString.replaceAll(Pattern.quote(salt), "").trim();
	    				    
	//    				    System.out.println("is this your password? " + foundPassword);
	    				    
	    				    if(foundPassword.equals(password)) {
	    				    	int[] ack = encryptString("ACK", k);
	    				    	sendMessage(ack);
	    				    }
	    				    else {
//		    			    	System.out.println("wrong password " + foundPassword);
	    				    	int[] error = encryptString("ERROR", k);
	    				    	sendMessage(error);
	    				    }
	    			    }catch (NullPointerException e) {
	    			    	System.out.println("user not found error");
	    			    	int[] error = encryptString("ERROR", k);
	    			    	sendMessage(error);
	    			    }
	    			    
	    			    String loginResponse = decryptintarr((int[])in.readObject(), k).trim();
	//    			    System.out.println("client login response " + loginResponse);
	    			    
	    			    if (loginResponse.equals("again")) {
	    			    	loggingin = true;
	    			    }
	    			    else if (loginResponse.equals("finished")){

	    			    	threadRunning = false;
	    			    }
	    			    else if (loginResponse.equals("filename")){
	    			    	loggingin = false;
	    			    }
	    		    }
	    		    String readingFile = "continue";
	    		    while (!readingFile.equals("finished")) {
	    			    int[] filenameint = (int[])in.readObject();
	    			    String filename = decryptintarr(filenameint, k).trim();
	    			    
	//    			    System.out.println("filename with decryption: " + filename);
	    			    
	    			    try {
	    				    File file = new File(filename);
	    				    byte[] fileContent = Files.readAllBytes(file.toPath());
	    				  	    
	    				    String fileContentString = new String(fileContent, "UTF-8");
	    				    sendMessage(encryptString("found", k));
	    				    sendMessage(encryptString(fileContentString, k));
	    			    }
	    			    catch (Exception e) {
//	    			    	System.out.println("error in finding file");
	    			    	sendMessage(encryptString("file not found", k));
	    			    }
	    			    readingFile = decryptintarr((int[])in.readObject(), k).trim();
	    		    }
    			}
    	  	  }
    		    
    		   catch (IOException e) {
    		  	    System.out.println("a client disconnected");
//    		  	    System.exit(-1);
    		  	  
    	  	  } catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
    	  		  System.out.println("invalid algorithm string");
				e1.printStackTrace();
			} catch (ClassNotFoundException e1) {
				// TODO Auto-generated catch block
				System.out.println("Class not found");
				e1.printStackTrace();
			} catch (InvalidKeyException e1) {
				// TODO Auto-generated catch block
				System.out.println("invalid key");
				e1.printStackTrace();
			}finally{
    		    try{
    		        in.close();
    		        out.close();
    		        clientServerSocket.close();
    		        this.stop();
    		    }
    		    catch(IOException ioException){
    		        ioException.printStackTrace();
    		    }
    	  	  }
    	    
    	    
    	}
    	
        void sendMessage(Object msg)
        {
            try{
                out.writeObject(msg);
                out.flush();
//                System.out.println("server>" + msg);
            }
            catch(IOException ioException){
                ioException.printStackTrace();
            }
        }
    }
    
}
