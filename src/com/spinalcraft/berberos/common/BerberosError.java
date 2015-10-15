package com.spinalcraft.berberos.common;

public class BerberosError {
	public static enum ErrorCode{CONNECTION, AUTHENTICATION, SECURITY};
	
	public ErrorCode error;
	public String message = "";
	
	public BerberosError(ErrorCode error){
		this.error = error;
	}
	
	public BerberosError(ErrorCode error, String message){
		this.error = error;
		this.message = message;
	}
}
