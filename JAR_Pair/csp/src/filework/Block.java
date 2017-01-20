package filework;

import java.io.*;
import java.security.NoSuchAlgorithmException;

public class Block {
	String identifier;
	FileData file;
	String hashID = "not initialized";
	String blockHash;
	int version;
	
	public Block(String id){
		this.identifier = id;
		try {
			hashID = SHA1.sha1(identifier);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}				
	}
	
	public Block(String id, FileData f){
		this(id);
		this.file = f;
	}
	
	public int getVersion(){
		return this.version;
	}
	
	public void setVersion(int ver){
		this.version = ver;
	}
	
	public void updateVersion(){
		version ++;
	}
	
	public String getHashID(){
		return hashID;
	}
	
	public String getBlockID(){
		return identifier;
	}
	public String hashBlock(){
		String[] fileid_array = identifier.split("\\.");
		
		boolean isJar = true;
		String location;
		
		if(!isJar)			
			location = fileid_array[0]+"/encrypted";	//run in eclipse
		else
			location = "/"+fileid_array[0]+"/encrypted";	//for jar
		
		StringBuffer content = new StringBuffer();
		byte[] read_array = new byte[200];	
		int readsize;
		
		//read
		InputStream readEncrypt;
		try {
			if(!isJar)
				readEncrypt = new FileInputStream(location);	//run in eclipse
			else
				readEncrypt = this.getClass().getResourceAsStream(location);//for jar
			while((readsize=readEncrypt.read(read_array)) != -1){
				content.append(new String(read_array, 0, readsize));
			}
			readEncrypt.close();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
		String blockHash = "not initialized";
		try {
			blockHash = SHA1.sha1(content.toString());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}		
		System.out.println("blockHash = "+blockHash);
		
		return blockHash;
	}
	
	public String updateBlock(){
		//boolean renew = false;
		String location_read = "blocks_pre/";
		String location_write = "blocks/";
		System.out.println("fileID: "+identifier);
		try {
			//1: copy content
			BufferedWriter renew_en = new BufferedWriter(new FileWriter(location_write + identifier));
			BufferedReader read_en = new BufferedReader(new FileReader(location_read+identifier));
			String str_en;
			String[] array_en;
			while((str_en = read_en.readLine()) != null){
				array_en = str_en.split("#");
				if(array_en[0].equals("blockHash")){
					blockHash = array_en[1];
					System.out.println("blockHash in file: "+blockHash);
				}else if(array_en[0].equals("signature")){
					BufferedWriter sig = new BufferedWriter(new FileWriter(location_write+identifier+".sig", false));
					sig.write(array_en[1]+"\n");
					sig.close();
				}else{
					renew_en.write(str_en+"\n");
				}
			}
			renew_en.close();
			read_en.close();
			
			//2: copy signature
			/*renew_en = new BufferedWriter(new FileWriter(location+identifier+".sig"));
			read_en = new BufferedReader(new FileReader(identifier+".sig"));
			while((str_en = read_en.readLine()) != null){
				renew_en.write(str_en+"\n");
			}
			renew_en.close();
			read_en.close();*/
			
			//3: modify file info in jar
			//ModifyJar mj = new ModifyJar();
			//mj.updateJarFile("blockID.txt", identifier, blockHash);
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		//return renew;
		return blockHash;
	}
}
