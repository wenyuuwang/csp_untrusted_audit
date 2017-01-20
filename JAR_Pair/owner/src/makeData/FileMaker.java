package makeData;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;


public class FileMaker {
	String filename;
	
	public FileMaker(String name){
		filename = name;
	}
	
	/**
	 * Encrypt file(filename)
	 * All files to be encrypted should be located directly in "file/" directory.
	 */
	public void encryptFile(){

		String location = "file/";
		String[] name_array = filename.split("\\.");
		String file_en = location + name_array[0] + "_encrypt.txt";	

		try {			
			//writer
			BufferedWriter write_en = new BufferedWriter(new FileWriter(file_en, false));
			
			//reader
			BufferedReader read_plain = new BufferedReader(new FileReader(location+filename));
			
			//work:
			String str_plain;
			String strKey = "file_key";
			while((str_plain = read_plain.readLine()) != null){
				write_en.write(Encrypt.encrypt(str_plain, strKey)+"\n");
			}	
			read_plain.close();
			write_en.close();
		} catch (IOException e) {
			e.printStackTrace();
		}	

	}
	/**
	 * Calculate file hash value and append the string to file. 
	 * Then append signature.
	 */
	public void addHashSig(){
		String location = "file/";
		String[] name_array = filename.split("\\.");
		String file_en = location + name_array[0] + "_encrypt.txt";		
		
		String str_en;
		StringBuffer content = new StringBuffer();
		try {
			BufferedReader read_en = new BufferedReader(new FileReader(file_en));
			while((str_en = read_en.readLine()) != null){
				content.append(str_en+"\n");
			}
			read_en.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		String blockHash = "not initialized";
		try {
			BufferedWriter write_hashSig = new BufferedWriter(new FileWriter(file_en, true));
			blockHash = Encrypt.sha1(content.toString());
			write_hashSig.write("blockHash#"+blockHash+"\n");
			write_hashSig.close();
			Encrypt.sign_file(name_array[0] + "_encrypt.txt");		
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}		
		System.out.println("blockHash = "+blockHash);
	}
}
