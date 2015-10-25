package com.spinalcraft.berberos.client;

import javax.crypto.SecretKey;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.spinalcraft.easycrypt.EasyCrypt;

public class AccessPackage {
	public SecretKey sessionKey;
	public String serviceTicket;
	public String serviceAddress;
	public int servicePort;
	
	public static AccessPackage fromJson(String json, EasyCrypt crypt){
		JsonParser parser = new JsonParser();
		JsonObject obj = parser.parse(json).getAsJsonObject();
		
		if(obj == null)
			return null;
		
		String sessionKeyString = obj.get("sessionKey").getAsString();
		if(sessionKeyString == null)
			return null;
		
		AccessPackage accessPackage = new AccessPackage();
		accessPackage.sessionKey = crypt.loadSecretKey(sessionKeyString);
		accessPackage.serviceTicket = obj.get("serviceTicket").getAsString();
		accessPackage.serviceAddress = obj.get("serviceAddress").getAsString();
		accessPackage.servicePort = obj.get("servicePort").getAsInt();
		return accessPackage;
	}
	
	public String toJson(EasyCrypt crypt){
		String sessionKeyString = crypt.stringFromSecretKey(sessionKey);
		JsonObject obj = new JsonObject();
		obj.addProperty("sessionKey", sessionKeyString);
		obj.addProperty("serviceTicket", serviceTicket);
		obj.addProperty("serviceAddress", serviceAddress);
		obj.addProperty("servicePort", servicePort);
		return obj.toString();
	}
}
