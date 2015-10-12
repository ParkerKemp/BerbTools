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
	private String identity;
	private SecretKey secretKey;
	private EasyCrypt crypt;
	
	public BerberosService(){
	}
	
	public boolean init(String identity, String accessKey, EasyCrypt crypt){
		this.crypt = crypt;
		this.identity = identity;
		String secretKeyString = retrieveSecretKey();
		if(secretKeyString != null)
			secretKey = crypt.loadSecretKey(secretKeyString);
		else{
			secretKey = register(accessKey);
			if(secretKey == null)
				return false;
		}
		return true;
	}
	
	private SecretKey register(String accessKey){
		Socket socket = new Socket();
		try {
			KeyPair keyPair = crypt.generateKeys();
			socket.connect(new InetSocketAddress("auth.spinalcraft.com", 9494), 5000);
			MessageSender sender = getSender(socket, crypt);
			sender.addHeader("intent", "registerService");
			sender.addItem("identity", identity);
			sender.addItem("publicKey", crypt.stringFromPublicKey(keyPair.getPublic()));
			sender.addItem("accessKey", accessKey);
			sender.sendMessage();
			
			MessageReceiver receiver = getReceiver(socket, crypt);
			if(!receiver.receiveMessage())
				return null;
			if(receiver.getHeader("status").equals("good")){
				byte[] secretKeyCipher = crypt.decode(receiver.getItem("secretKey"));
				SecretKey key = crypt.decryptKey(keyPair.getPrivate(), secretKeyCipher);
				storeSecretKey(crypt.stringFromSecretKey(key));
				return key;
			}
		} catch (IOException | GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public ServiceAmbassador getAmbassador(Socket socket){
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
	}
	
	protected abstract void storeSecretKey(String secretKey);
	
	protected abstract String retrieveSecretKey();
}
