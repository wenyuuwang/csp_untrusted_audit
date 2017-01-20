package access;


import filework.*;
public class User {
	protected int userID;
	protected int randomID;
	protected String hashID;
	protected int version;
	private boolean valid;
	
	public User(int i){	//not applied to jar
		userID = i;
	}
	
	public User(){
		
	}
	
	public User(String hashID){
		this.hashID = hashID;
	}
	

	public void setHashID(String hash){
		hashID = hash;
	}
	
	public String getHashID(){
		return hashID;
	}
	
	public void setValid(){
		valid = true;
	}
	
	public void setVersion(int v){
		this.version = v;
	}
	
	public int getVersion(){
		return version;
	}
	
	/**
	 * make url and Permission for user;
	 * Sorry: currently there is no permission generation procedure in this method. 
	 * @param f
	 */
	public void read(FileData f){
		if(valid){
			AccessFile readCloud = new AccessFile();
			readCloud.makeURL(f.getName());
			//make Permission&signature heres
		}else
			System.out.println("Again: not permitted");
	}
	
}
