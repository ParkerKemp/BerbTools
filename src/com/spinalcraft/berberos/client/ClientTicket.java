package com.spinalcraft.berberos.client;

import javax.crypto.SecretKey;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.spinalcraft.easycrypt.EasyCrypt;

public class ClientTicket {
	public String identity;
	public String serviceAddress;
	public int servicePort;
	public long expiration;
	public SecretKey sessionKey;
	
	private EasyCrypt crypt;
	
	public ClientTicket(EasyCrypt crypt){
		this.crypt = crypt;
	}
	
	public static ClientTicket fromCipher(String cipher, SecretKey secretKey, EasyCrypt crypt){
		ClientTicket ticket = new ClientTicket(crypt);
		String json = crypt.decryptMessage(secretKey, crypt.decode(cipher));
		if(json == null){
			System.err.println("Failed to decrypt Json.");
			return null;
		}
		try{
			JsonParser parser = new JsonParser();
			JsonObject obj = parser.parse(json).getAsJsonObject();
			ticket.identity = obj.get("identity").getAsString();
			ticket.serviceAddress = obj.get("serviceAddress").getAsString();
			ticket.servicePort = obj.get("servicePort").getAsInt();
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
		obj.addProperty("identity", identity);
		obj.addProperty("serviceAddress", serviceAddress);
		obj.addProperty("servicePort", servicePort);
		obj.addProperty("expiration", expiration);
		obj.addProperty("sessionKey", crypt.stringFromSecretKey(sessionKey));
		return obj;
	}
}
