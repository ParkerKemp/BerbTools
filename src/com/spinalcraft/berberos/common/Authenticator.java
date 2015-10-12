package com.spinalcraft.berberos.common;

import javax.crypto.SecretKey;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.spinalcraft.easycrypt.EasyCrypt;

public class Authenticator {
	public String identity;
	public long timestamp;
	
	public static Authenticator fromCipher(String cipher, SecretKey secretKey, EasyCrypt crypt){
		Authenticator authenticator = new Authenticator();
		String json = crypt.decryptMessage(secretKey, cipher.getBytes());
		if(json == null){
			return null;
		}
		try{
			JsonParser parser = new JsonParser();
			JsonObject obj = parser.parse(json).getAsJsonObject();
			authenticator.identity = obj.get("identity").getAsString();
			authenticator.timestamp = obj.get("timestamp").getAsLong();
			return authenticator;
		}catch(JsonParseException e){
			return null;
		}
	}
	
	public JsonObject getJson(){
		JsonObject obj = new JsonObject();
		obj.addProperty("identity", identity);
		obj.addProperty("timestamp", timestamp);
		return obj;
	}
}
