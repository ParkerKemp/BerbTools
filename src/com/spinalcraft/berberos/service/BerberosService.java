package com.spinalcraft.berberos.service;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import javax.crypto.SecretKey;
import com.spinalcraft.berberos.common.Authenticator;
import com.spinalcraft.berberos.common.BerberosEntity;
import com.spinalcraft.berberos.common.ClientTicket;
import com.spinalcraft.easycrypt.EasyCrypt;
import com.spinalcraft.easycrypt.messenger.MessageReceiver;
import com.spinalcraft.easycrypt.messenger.MessageSender;

public abstract class BerberosService extends BerberosEntity{
	private SecretKey secretKey;
	private EasyCrypt crypt;
	
	public BerberosService(String accessKey, EasyCrypt crypt){
		this.crypt = crypt;
		secretKey = crypt.loadSecretKey(retrieveSecretKey());
		if(secretKey == null)
			if(register(accessKey))
				secretKey = crypt.loadSecretKey(retrieveSecretKey());
	}
	
	private boolean register(String accessKey){
		if(retrieveSecretKey() != null){
			return true;
		}
		Socket socket = new Socket();
		try {
			KeyPair keyPair = crypt.generateKeys();
			socket.connect(new InetSocketAddress("auth.spinalcraft.com", 9494), 5000);
			MessageSender sender = getSender(socket, crypt);
			sender.addHeader("intent", "serviceAuth");
			sender.addItem("publicKey", crypt.stringFromPublicKey(keyPair.getPublic()));
			sender.addItem("accessKey", accessKey);
			sender.sendMessage();
			
			MessageReceiver receiver = getReceiver(socket, crypt);
			receiver.receiveMessage();
			if(receiver.getHeader("status").equals("good")){
				String secretKey = receiver.getItem("secretKey");
				storeSecretKey(secretKey);
				return true;
			}
		} catch (IOException | GeneralSecurityException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	public ServiceAmbassador getClientHandler(Socket socket){
		MessageReceiver receiver = getReceiver(socket, crypt);
		receiver.receiveMessage();
		String ticketCipher = receiver.getItem("ticket");
		String authCipher = receiver.getItem("authenticator");
		
		if(authenticatorCached(authCipher))
			return null;
		
		ClientTicket ticket = ClientTicket.fromCipher(ticketCipher, secretKey, crypt);
		if(ticket == null)
			return null;
		
		Authenticator authenticator = Authenticator.fromCipher(authCipher, ticket.sessionKey, crypt);
		
		if(validTicket(ticket) && validAuthenticator(authenticator, ticket) && cacheAuthenticator(authCipher))
			return new ServiceAmbassador(socket, ticket.sessionKey, crypt, this);
		return null;
	}
	
	protected abstract boolean authenticatorCached(String authenticator);
	
	protected abstract boolean cacheAuthenticator(String authenticator);
	
	private boolean validTicket(ClientTicket ticket){
		return ticket.expiration > System.currentTimeMillis() / 1000;
	}
	
	private boolean validAuthenticator(Authenticator authenticator, ClientTicket ticket){
		return authenticator.identity.equals(ticket.identity);
//		String json = crypt.decryptMessage(ticket.sessionKey, authenticator.getBytes());
//		if(json == null){
//			return false;
//		}
//		try{
//			JsonParser parser = new JsonParser();
//			JsonObject obj = parser.parse(json).getAsJsonObject();
//			String identity = obj.get("identity").getAsString();
//			
//			long timestamp = obj.get("timestamp").getAsLong();
//			
//			return identity.equals(ticket.identity);
//		}catch(JsonParseException e){
//			return false;
//		}
	}
	
	protected abstract void storeSecretKey(String secretKey);
	
	protected abstract String retrieveSecretKey();
}
