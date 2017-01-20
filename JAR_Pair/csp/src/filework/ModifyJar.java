package filework;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.jar.*;

import javax.swing.JOptionPane;


public class ModifyJar {
	
	/**
	 * for both group and block record in jar. 
	 * @param filename
	 * @param blockID
	 * @param blockHash
	 */
	public void updateJarFile(String filename, String blockID, String blockHash){
		
		String location = "text/";
		String originalPath = getClass().getProtectionDomain().getCodeSource().getLocation().getPath();
		System.out.println("original path:" + originalPath);
		String tempPath = originalPath.substring(0, originalPath.length()-4) + "_temp.jar";  
	    
		JarFile originalJar = null; 
        try { 
            originalJar = new JarFile(originalPath); 
        } catch (IOException e1) { 
            e1.printStackTrace(); 
        } 
        List<JarEntry> lists = new LinkedList<JarEntry>(); 
        for(Enumeration<JarEntry> entrys = originalJar.entries(); entrys.hasMoreElements();) { 
            JarEntry jarEntry = entrys.nextElement(); 
            //System.out.println(jarEntry.getName());  
            lists.add(jarEntry); 
        } 
        File handled = new File(tempPath); 
        JarOutputStream jos = null; 
        try { 
            FileOutputStream fos = new FileOutputStream(handled); 
            jos = new JarOutputStream(fos); 
             
            /**
             * 将源文件中的内容复制过来~
             * 可以利用循环将一个文件夹中的文件都写入jar包中 其实很简单
             */ 
            for(JarEntry je : lists) { 
                // jar 中的每一个文件夹 每一个文件 都是一个 jarEntry  
                JarEntry newEntry = new JarEntry(je.getName()); 	                 
//              newEntry.setComment(je.getComment());  
//              newEntry.setCompressedSize(je.getCompressedSize());  
//              newEntry.setCrc(je.getCrc());  
//              newEntry.setExtra(je.getExtra());  
//              newEntry.setMethod(je.getMethod());  
//              newEntry.setTime(je.getTime());  
//              System.out.println(je.getAttributes());  
                /** 这句代码有问题，会导致将jar包重命名为zip包之后无法解压缩~ */ 
//              newEntry.setSize(je.getSize());  
	                 
	            // 表示将该entry写入jar文件中 也就是创建该文件夹和文件  
	            jos.putNextEntry(newEntry); 
	             
	            //此处更新valid_user.txt 文件
	            String[] array_name = filename.split("_");	//for group dynamics
	            //String filename0 = array_name[0]+"_"+array_name[1]+"_"+array_name[3];	//for group dynamics
	            //System.out.println("filename0: "+filename0);
	            //if(je.getName().equals(location+filename0)) { 	//for group dynamics
	            if(je.getName().equals(location+filename)) {
	            	System.out.println("file to be modified: "+ filename );
	            	if(array_name[0].equals("valid"))
	            		updateACL(filename, jos);
	            	else if(filename.equals("blockID.txt"))
	            		updateBLC(filename, jos, blockID, blockHash);
	            	else
	            		System.out.println("no such file: "+filename);
	                continue; 
	            }
	             
	            InputStream is = originalJar.getInputStream(je); 
	            byte[] bytes = inputStream2byteArray(is); 
	            is.close(); 
	             
	            // 然后就是往entry中的jj.txt文件中写入内容  
	            jos.write(bytes); 
            } 
            // 最后不能忘记关闭流  
            jos.close(); 
            fos.close(); 
             
            /** 删除原始文件，将新生成的文件重命名为原始文件的名称~ */ 
            File original = new File(originalPath);
            original.delete(); 
            handled.renameTo(new File(originalPath)); 
           
        } catch (Exception e1) { 
            e1.printStackTrace(); 
        }  
	}
	
	public String updateACL(String filename, JarOutputStream jos){
		String str_modify;
		String [] array_modify;
		//StringBuffer revoke_ids = new StringBuffer();
		ArrayList<String> revoke_users = new ArrayList<String>();
		try {
			BufferedReader read_modify = new BufferedReader(new FileReader(filename));
			while((str_modify = read_modify.readLine()) != null){
				//System.out.println(str_modify);
				array_modify = str_modify.split("#");
				if(array_modify[0].equals("add"))
					jos.write((array_modify[1]+"\n").getBytes());
				else if(array_modify[0].equals("sharingGroup"))
					jos.write((str_modify+"\n").getBytes());
				else if(array_modify[0].equals("revoke")){
					//revoke_ids.append(array_modify[1]+":");
					revoke_users.add(array_modify[1]);
				}
			}
			read_modify.close();
			//if user is not revoked, copy them to jar
			String location = "/text/";
			//BufferedReader read_list = new BufferedReader(new FileReader(location+filename));
			InputStream strm = this.getClass().getResourceAsStream(location+"valid_user_en.txt");	//for jar
			BufferedReader read_list = new BufferedReader(new InputStreamReader(strm, "UTF-8")); 
			String str_list;
			boolean found = false;
			System.out.println("current: "+read_list.readLine());
			while((str_list = read_list.readLine()) != null){
				//System.out.println(str_list);
				found = false;
				for(String user : revoke_users){
					if(user.equals(str_list)){
						found = true;
						//System.out.println("found here");
						//break;
					}					
				}
				if(!found){
					String[] array_list = str_list.split("#");
					if(!array_list[0].equals("signature"))
						jos.write((str_list+"\n").getBytes());
				}
			}
			read_list.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	
	public void updateBLC(String filename, JarOutputStream jos, String blockIDs, String blockHashes){
		
		try {
			String location = "/text/";
			InputStream strm = this.getClass().getResourceAsStream(location+filename);	//for jar
			BufferedReader read_current = new BufferedReader(new InputStreamReader(strm, "UTF-8")); 
			StringBuffer hashes = new StringBuffer();
			String[] array_content;
			String[] array_blockID = blockIDs.split("#");
			String[] array_blockHash = blockHashes.split("#");
			if(array_blockID.length != array_blockHash.length)
				System.out.println("number of id and hash do not match =_=");
			String str_content;
			while((str_content = read_current.readLine()) != null){
				array_content = str_content.split("#");
				if(array_content[0].equals("file")){
					int f_version = (Integer.parseInt(array_content[1]));
					String f_hash = SHA1.sha1(hashes.toString());
					System.out.println("file#"+(f_version+1)+"#"+f_hash);
					jos.write(("file#"+(f_version+1)+"#"+f_hash+"\n").getBytes());
				}else{
					boolean match = false;
					for(int i=0; i<array_blockID.length; i++){
						if(array_content[0].equals(array_blockID[i])){
							match = true;
							int version = (Integer.parseInt(array_content[1]));
							System.out.println(array_blockID[i]+"#"+(version+1)+"#"+array_blockHash[i]);
							jos.write((array_blockID[i]+"#"+(version+1)+"#"+array_blockHash[i]+"\n").getBytes());
							hashes.append(array_blockHash[i]);
							break;
						}
					}
					if(!match){
						jos.write((str_content+"\n").getBytes());
						hashes.append(array_content[2]);
					}
				}
				/*if(array_content[0].equals(blockID)){
					int version = (Integer.parseInt(array_content[1]));
					System.out.println(blockID+"#"+(version+1)+"#"+blockHash);
					jos.write((blockID+"#"+(version+1)+"#"+blockHash+"\n").getBytes());
					hashes.append(blockHash);
				} else if(array_content[0].equals("file")){
					int f_version = (Integer.parseInt(array_content[1]));
					String f_hash = SHA1.sha1(hashes.toString());
					System.out.println("file#"+(f_version+1)+"#"+f_hash);
					jos.write(("file#"+(f_version+1)+"#"+f_hash+"\n").getBytes());
				} else{
					jos.write((str_content+"\n").getBytes());
					hashes.append(array_content[2]);
				}*/
				//System.out.println(hashes);
			}
			read_current.close();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	public static byte[] inputStream2byteArray(InputStream is) { 
	    ByteArrayOutputStream baos = new ByteArrayOutputStream(); 
	    int i; 
	    try { 
	        while((i = is.read()) != -1) { 
	            baos.write(i); 
	        } 
	        baos.close(); 
	    } catch (IOException e) { 
	        e.printStackTrace(); 
	    } 
	    byte[] bytes = baos.toByteArray(); 
	    return bytes; 
	} 
}
