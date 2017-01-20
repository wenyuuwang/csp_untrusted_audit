package frame;

import access.Authorization;
import access.User;
import filework.FileData;

public class testOH {
	public static void main(String[] args){
		
		
		Authorization judge = new Authorization();
		User u = new User("hashID");
		u.setVersion(0);
		
		FileData f = new FileData("text.txt");
		judge.makeAttest(u, f);		
	}
}
