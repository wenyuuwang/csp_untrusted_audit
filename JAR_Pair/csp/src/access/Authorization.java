package access;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.swing.JOptionPane;

import filework.*;

import java.text.SimpleDateFormat;



public class Authorization {
	
	public Authorization(){
		
	}
		
	// look up userID. delete later
	/*public String getHashID(int userID){
		String hashID = null;
		int count = 0;
		try{
			BufferedReader userReader = new BufferedReader(new FileReader("/HashUser.txt"));
			hashID = userReader.readLine();
			while( hashID != null && count < userID){
				count ++;
				hashID = userReader.readLine();
			}
			userReader.close();
		}catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		return hashID;
	}*/
	
	/**
	 * To check if user is in sharing group
	 */
	public boolean isValid(User u, String blockID){
		String userHash = u.getHashID();
		boolean isValid = false;
		int count = 0;
		String[] blockid_array = blockID.split("\\.");
		
		boolean isJar = true;
		String location;
		
		if(!isJar)
			location = blockid_array[0]+"/valid_user.txt";	//run in eclipse
		else
			location = "/text/valid_user_en.txt";	//for jar
		
		BufferedReader userReader;
		
		try{
			if(isJar){
				InputStream strm = this.getClass().getResourceAsStream(location);	//for jar
				userReader = new BufferedReader(new InputStreamReader(strm, "UTF-8")); //for jar
				//test input
				
			}else			
				userReader = new BufferedReader(new FileReader(location));//run in eclipse
			
			//read 1st line to check version
			String[] array_content = userReader.readLine().split("#");
			if(Integer.parseInt(array_content[1]) == u.getVersion())
				System.out.println("user list version OK");
			else{
				System.out.println("user list version problem");
				return false;
			}
			//continue reading to check userHashID
			String hashID = userReader.readLine();			
			String userHash_en = AES128.encrypt(userHash, "userlist_key");
			System.out.println("user: " + userHash_en);
			while( hashID != null){
				if(userHash_en.equals(hashID)){
					isValid = true;
					//System.out.println("count = "+count);
					userReader.close();
					break;
				}
				hashID = userReader.readLine();
				count ++;
			}
			System.out.println("count = "+count);
			userReader.close();
		}catch (IOException e) {
			e.printStackTrace();
		}
		//csp make permission for valid user request
		if(isValid){
			try {
				BufferedWriter make_permission = new  BufferedWriter(new FileWriter("permission.txt"));
				BufferedReader read_req = new BufferedReader(new FileReader("request.txt"));
				String req[] = read_req.readLine().split("#",2);
				make_permission.write("PERMIT#"+req[1]+"\n");
				make_permission.close();
				read_req.close();
				VerifySig.sign_file("permission.txt");
				System.out.println("permission signed");
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return isValid;
		
	}
	
	/**
	 * This method makes attestation with multiple steps involved in chainHash
	 * Slows down the process of attestation generation
	 * Maybe fewer OH will improve speed
	 * @param u
	 * @param f
	 */
	public void makeAttest_withOH(User u, FileData f){
		//0:
		String str = MD5.initialize();
		System.out.println(str);
		//blockhashid+ver+hash + userhashid+ver + time + lsn + chainhash
		
		String blockHash = f.readFileHash();
		String blockHashID = f.getHashID();
		
		//1.1:
		System.out.println(f.getName());
		str = MD5.update(str, f.getName());
		System.out.println(str);
		//1.2:
		str = MD5.update(str, blockHashID);
		System.out.println(str);
				
		int file_ver = f.getVersion();
		int lsn = Integer.MIN_VALUE;
		
		//2:
		str = MD5.update(str, ""+lsn);
		System.out.println(str);
		
		String userHash = u.getHashID();
		int user_ver = u.getVersion();
		
		SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMdd－hh:mm");
		String time = formatter.format(new Date());
		
		//read last lsn from file
		try {
			BufferedReader lsn_reader = new BufferedReader(new FileReader("attest/LSN.txt"));
			String str1, str2 = ""+Integer.MIN_VALUE;
			while((str1 = lsn_reader.readLine()) != null){
				str2 = str1;
				//System.out.println(str2);
			}
			lsn = Integer.parseInt(str2) + 1;
			
			//3:
			str = MD5.update(str, ""+ (lsn-Integer.parseInt(str2)) );
			System.out.println(str); 
			
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		//make attestation data
		StringBuffer attest = new StringBuffer();		
		attest.append(blockHashID);
		attest.append(String.format("%04d", file_ver));
		attest.append(blockHash);
		attest.append(userHash);
		attest.append(String.format("%04d", user_ver));
		attest.append(time);
		attest.append(String.format("%07d", lsn));
		//get previous chainHash
		String prevAttest = "attest/"+String.format("%07d", lsn-1)+".txt";
		String prevChainHash = "blank";
		try {
			RandomAccessFile readPrev = new RandomAccessFile(prevAttest, "r");
			readPrev.seek(149);
			byte[] chain_array = new byte[40];
			readPrev.read(chain_array);
			prevChainHash = new String(chain_array);
			//System.out.println("prev-chain = " + prevChainHash);
			
			//4:
			str = MD5.update(str, "read_prev_chainHash" );
			System.out.println(str); 
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		//calculate new chainHash
		String chainHash = "blank chain";
		try {
			chainHash = SHA1.sha1(attest.toString() + prevChainHash);
			
			//5:
			str = MD5.update(str, "cal_new_chainHash" );
			System.out.println(str); 
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		attest.append(chainHash);
	
		
		//make attestation file
		String attestFile = "attest/"+String.format("%07d", lsn)+".txt";
		try {
			FileWriter makeAttest = new FileWriter(attestFile, false);
			//System.out.println(attest);
			makeAttest.write(attest.toString());
			makeAttest.close();
			
			//6:
			str = MD5.update(str, "attest.txt" );
			System.out.println(str); 
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		//append current lsn to file
		try {
			
			str = MD5.update(str, "add current LSN to file" );
			System.out.println("final: "+str); 
			if(MD5.validate(str, "6ac89c8cf715e2b731c28a57ad848344")){
				BufferedWriter lsn_writer = new BufferedWriter(new FileWriter("attest/LSN.txt", true));
				lsn_writer.write(""+lsn+"\n");
				lsn_writer.close();
			}else{
				JOptionPane.showMessageDialog(null, "OH problem ", "Message",JOptionPane.INFORMATION_MESSAGE, null);
				System.exit(0);
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * This method has been modified with an additional param: prev-chain
	 * shown in next method: String makeAttest(User u, FileData f, int index, String prev_chain)
	 * @param u
	 * @param f
	 * @param index
	 * @return
	 */
	public String makeAttest(User u, FileData f, int index){
	
	//e1b61da3c6ad891b0e46ded6b7399f49
	
		//String blockHash = f.readFileHash();
		String blockHash = "c850b9c8461fa0cd791020e0135";
		String blockHashID = f.getHashID();	
		String userHash = u.getHashID();
		int user_ver = u.getVersion();
		
		SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMdd－hh:mm");
		String time = formatter.format(new Date());
		
		//make attestation data
		StringBuffer attest = new StringBuffer();		
		attest.append(blockHashID);
		attest.append(blockHash);
		attest.append(userHash);
		attest.append(String.format("%04d", user_ver));
		attest.append(time);
		//get previous chainHash
		String prevAttest = "attest/"+String.format("%07d", index)+".txt";
		String prevChainHash = "blank";
		try {
			RandomAccessFile readPrev = new RandomAccessFile(prevAttest, "r");
			readPrev.seek(149);
			byte[] chain_array = new byte[40];
			readPrev.read(chain_array);
			prevChainHash = new String(chain_array);
			//System.out.println("prev-chain = " + prevChainHash);
			readPrev.close();
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		//calculate new chainHash
		String chainHash = "blank chain";
		try {
			chainHash = SHA1.sha1(attest.toString() + prevChainHash);
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		attest.append(chainHash+"\n");
			
		//sign file
		attest.append(VerifySig.sign_file_return(attest.toString()));
		
	
		//make attestation file
		String attestFile = "attest/"+String.format("%07d", index+1)+".txt";
		try {
			FileWriter makeAttest = new FileWriter(attestFile, false);
			makeAttest.write(attest.toString());
			makeAttest.close();			
		} catch (IOException e) {
			e.printStackTrace();
		}
		return chainHash.toString();
	}

	/**
	 * Newest attestation generation method. 
	 * Improvements from last version: 
	 * 		Previous ChainHash is stored as a program parameter, not in a file, leading to enhenced security
	 * Notice: no OH in this method. 
	 * See makeAttestwithOH to add some OH
	 * @param u
	 * @param f
	 * @param index
	 * @param prev_chain
	 * @return
	 */
	public String makeAttest(User u, FileData f, int index, String prev_chain){
		
		//e1b61da3c6ad891b0e46ded6b7399f49
		
			//String blockHash = f.readFileHash();
			String blockHash = "c850b9c8461fa0cd791020e0135";
			String blockHashID = f.getHashID();	
			String userHash = u.getHashID();
			int user_ver = u.getVersion();
			
			SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMdd－hh:mm");
			String time = formatter.format(new Date());
			
			//make attestation data
			StringBuffer attest = new StringBuffer();		
			attest.append(blockHashID);
			attest.append(blockHash);
			attest.append(userHash);
			attest.append(String.format("%04d", user_ver));
			attest.append(time);
			
			//calculate new chainHash
			String chainHash = "blank chain";
			try {
				chainHash = SHA1.sha1(attest.toString() + prev_chain);
				
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
			attest.append(chainHash+"\n");
				
			//sign file
			attest.append(VerifySig.sign_file_return(attest.toString()));
				
			//make attestation file
			String attestFile = "attest/"+String.format("%07d", index+1)+".txt";
			try {
				FileWriter makeAttest = new FileWriter(attestFile, false);
				makeAttest.write(attest.toString());
				makeAttest.close();			
			} catch (IOException e) {
				e.printStackTrace();
			}
			return chainHash.toString();
		}
	
	/**
	 * Replaced by next method 
	 * @param u
	 * @param f
	 * @param index
	 * @return
	 */
	public String makeDistributeAttest(User u, FileData f, int index){
		//String blockHash = "fileHash";		
		//String blockHashID = f.getHashID();		
		String userHash = u.getHashID();
		//int user_ver = u.getVersion();
		
		SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMdd－hh:mm");
		String time = formatter.format(new Date());
		
		//make attestation data
		StringBuffer attest = new StringBuffer();		
		//attest.append(blockHashID);
		//attest.append(blockHash);
		attest.append(userHash);
		//attest.append(String.format("%04d", user_ver));
		attest.append(time);
		//attest.append(String.format("%07d", lsn));
		//get previous chainHash
		String prevAttest = "attest/"+String.format("%07d", index)+".txt";
		String prevChainHash = "blank";
		try {
			RandomAccessFile readPrev = new RandomAccessFile(prevAttest, "r");
			readPrev.seek(149);
			byte[] chain_array = new byte[40];
			readPrev.read(chain_array);
			prevChainHash = new String(chain_array);
			//System.out.println("prev-chain = " + prevChainHash);
			readPrev.close();
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		//calculate new chainHash
		String chainHash = "blank chain";
		try {
			chainHash = SHA1.sha1(attest.toString() + prevChainHash);
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		attest.append(chainHash+"\n");
		
		//sign file
		attest.append(VerifySig.sign_file_return(attest.toString()));
		
		//rsa en
		StringBuffer encrypt_attest = new StringBuffer();
		String attest1 = attest.substring(0,120);
		String attest2 = attest.substring(121, 240);
		String attest3 = attest.substring(241, attest.length());
		try {
			encrypt_attest.append(RSAen.encrypt(attest1.toString()));
			encrypt_attest.append(RSAen.encrypt(attest2.toString()));
			encrypt_attest.append(RSAen.encrypt(attest3.toString()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		//make attestation file
		String attestFile = "attest/"+String.format("%07d", index+1)+".txt";
		try {
			FileWriter makeAttest = new FileWriter(attestFile, false);
			makeAttest.write(encrypt_attest.toString());
			makeAttest.close();			
		} catch (IOException e) {
			e.printStackTrace();
		}
		return chainHash.toString();

	}
	
	/**
	 * Notice: no OH in this method. 
	 * See makeAttestwithOH to add some OH 
	 * @param u
	 * @param f
	 * @param index
	 * @param prev_chain
	 * @return
	 */
	public String makeDistributeAttest(User u, FileData f, int index, String prev_chain){
		//String blockHash = "fileHash";		
		//String blockHashID = f.getHashID();		
		String userHash = u.getHashID();
		//int user_ver = u.getVersion();
		
		SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMdd－hh:mm");
		String time = formatter.format(new Date());
		
		//make attestation data
		StringBuffer attest = new StringBuffer();		
		//attest.append(blockHashID);
		//attest.append(blockHash);
		attest.append(userHash);
		//attest.append(String.format("%04d", user_ver));
		attest.append(time);
		//attest.append(String.format("%07d", lsn));
		
		//calculate new chainHash
		String chainHash = "blank chain";
		try {
			chainHash = SHA1.sha1(attest.toString() + prev_chain);
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		attest.append(chainHash+"\n");
		
		//sign file
		attest.append(VerifySig.sign_file_return(attest.toString()));
		
		//rsa en
		StringBuffer encrypt_attest = new StringBuffer();
		String attest1 = attest.substring(0,120);
		String attest2 = attest.substring(121, 240);
		String attest3 = attest.substring(241, attest.length());
		try {
			encrypt_attest.append(RSAen.encrypt(attest1.toString()));
			encrypt_attest.append(RSAen.encrypt(attest2.toString()));
			encrypt_attest.append(RSAen.encrypt(attest3.toString()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		//make attestation file
		String attestFile = "attest/"+String.format("%07d", index+1)+".txt";
		try {
			FileWriter makeAttest = new FileWriter(attestFile, false);
			makeAttest.write(encrypt_attest.toString());
			makeAttest.close();			
		} catch (IOException e) {
			e.printStackTrace();
		}
		return chainHash.toString();
	}
	
}
