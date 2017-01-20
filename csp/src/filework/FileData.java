package filework;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class FileData {
	String filename;
	String fileHash;
	String fileHashID;
	//ArrayList<Block> blocks;
	int version;
	
	public FileData(String str){
		filename = str;
		//blocks = new ArrayList<Block>();
		try {
			fileHashID = SHA1.sha1(filename);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}				
	}
	
	public String hashFile(){
		String hashBlocks = "not initialized";
		InputStream strm = this.getClass().getResourceAsStream(filename+"/blockID.txt");	//for jar
		try {
			BufferedReader read_index = new BufferedReader(new InputStreamReader(strm, "UTF-8"));
			String str_index;
			String[] array_index;
			StringBuffer content = new StringBuffer();
			while( (str_index = read_index.readLine()) != null){
				array_index = str_index.split("#");
				if(array_index[0].equals("file")){
					continue;
				} else{
					//blocks.add(new Block(array_index[0], this));
					content.append(array_index[2]);
				}											
			}	
			fileHash = SHA1.sha1(content.toString());
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return hashBlocks;
	}
	
	public String readFileHash(){
		String hashBlocks = "not initialized";
		String[] array_name = filename.split("\\.");
		//System.out.println("read from /"+array_name[0]+"/blockID.txt");
		InputStream strm = this.getClass().getResourceAsStream("/"+array_name[0]+"/blockID.txt");	//for jar
		try {
			BufferedReader read_index = new BufferedReader(new InputStreamReader(strm, "UTF-8"));
			String str_index;
			String[] array_index;
			while( (str_index = read_index.readLine()) != null){
				array_index = str_index.split("#");
				if(array_index[0].equals("file")){
					hashBlocks = array_index[2];
					version = Integer.parseInt(array_index[1]);
					break;
				} else{
					continue;
				}											
			}	
		} catch (IOException e) {
			e.printStackTrace();
		}
		return hashBlocks;
	}
	
	public String getName(){
		return filename;
	}
	
	public int getVersion(){
		return version;
	}
	
	public String getHashID(){
		return fileHashID;
	}
}
