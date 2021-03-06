package com.spinalcraft.berberos.service;

import javax.crypto.SecretKey;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.spinalcraft.easycrypt.EasyCrypt;

public class ServiceTicket {
	public String clientIdentity;
	public String serviceIdentity;
	public long expiration;
	public SecretKey sessionKey;
	
	private EasyCrypt crypt;
	
	public ServiceTicket(EasyCrypt crypt){
		this.crypt = crypt;
	}
	
	public static ServiceTicket fromCipher(String cipher, SecretKey secretKey, EasyCrypt crypt){
		ServiceTicket ticket = new ServiceTicket(crypt);
		String json = crypt.decryptMessage(secretKey, crypt.decode(cipher));
		if(json == null){
			System.err.println("Failed to decrypt Json.");
			return null;
		}
		try{
			JsonParser parser = new JsonParser();
			JsonObject obj = parser.parse(json).getAsJsonObject();
			ticket.clientIdentity = obj.get("clientIdentity").getAsString();
			ticket.serviceIdentity = obj.get("serviceIdentity").getAsString();
			ticket.expiration = obj.get("expiration").getAsLong();
			ticket.sessionKey = crypt.loadSecretKey(obj.get("sessionKey").getAsString());
			return ticket;
		}catch(JsonParseException e){
			System.err.println("Decrypted message was not valid Json.");
			return null;
		}
	}
	
	public JsonObject getJson(){
		JsonObject obj = new JsonObject();
		obj.addProperty("clientIdentity", clientIdentity);
		obj.addProperty("serviceIdentity", serviceIdentity);
		obj.addProperty("expiration", expiration);
		obj.addProperty("sessionKey", crypt.stringFromSecretKey(sessionKey));
		return obj;
	}
}
