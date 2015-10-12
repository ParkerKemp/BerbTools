package com.spinalcraft.berberos.service;

import java.net.Socket;

import javax.crypto.SecretKey;

import com.google.gson.JsonObject;
import com.spinalcraft.berberos.common.Ambassador;
import com.spinalcraft.berberos.common.Authenticator;
import com.spinalcraft.berberos.common.BerberosEntity;
import com.spinalcraft.easycrypt.EasyCrypt;
import com.spinalcraft.easycrypt.messenger.MessageSender;

public class ServiceAmbassador extends Ambassador{
	
	public ServiceAmbassador(Socket socket, SecretKey sessionKey, EasyCrypt crypt, BerberosEntity entity){
		super(socket, sessionKey, crypt, entity);
		sendAuthenticator();
	}
	
	private void sendAuthenticator(){
		MessageSender sender = entity.getSender(socket, crypt);
		sender.addHeader("status", "good");
		Authenticator authenticator = new Authenticator();
		authenticator.identity = "Service";
		authenticator.timestamp = System.currentTimeMillis() / 1000;
		JsonObject obj = authenticator.getJson();
		byte[] cipher = crypt.encryptMessage(sessionKey, obj.toString());
		sender.addItem("authenticator", crypt.encode(cipher));
		sender.sendMessage();
	}
}
