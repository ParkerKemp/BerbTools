package com.spinalcraft.berberos.client;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import com.spinalcraft.berberos.common.Authenticator;
import com.spinalcraft.berberos.common.BerberosEntity;
import com.spinalcraft.berberos.common.ClientTicket;
import com.spinalcraft.easycrypt.EasyCrypt;
import com.spinalcraft.easycrypt.messenger.MessageReceiver;
import com.spinalcraft.easycrypt.messenger.MessageSender;

public abstract class BerberosClient extends BerberosEntity{
	protected EasyCrypt crypt;
	
	public BerberosClient(EasyCrypt crypt){
		this.crypt = crypt;
	}
	
	public ClientAmbassador getAmbassador(Socket socket, String username, String password, String service){
		SecretKey secretKey = crypt.loadSecretKey(getHash(username, password));
		String serviceTicket = retrieveTicket(service);
		String sessionKeyString = retrieveSessionKey(service);
		SecretKey sessionKey;
		if(serviceTicket == null || sessionKeyString == null){
			MessageReceiver receiver = requestTicket(username, secretKey, service);
			if(receiver.getHeader("status").equals("bad"))
				return null;
			serviceTicket = extractServiceTicket(receiver, service);
			ClientTicket clientTicket = extractClientTicket(receiver, secretKey);
			sessionKey = clientTicket.sessionKey;
		}
		else{
			sessionKey = crypt.loadSecretKey(sessionKeyString);
		}
		
		if(serviceTicket == null)
			return null;

		sendHandshakeRequest(socket, username, sessionKey, serviceTicket);
		if(!receiveHandshakeResponse(socket, sessionKey, service))
			return null;
		
		ClientAmbassador ambassador = new ClientAmbassador(socket, sessionKey, crypt, this);

		return ambassador;
	}
	
	private boolean receiveHandshakeResponse(Socket socket, SecretKey sessionKey, String service){
		MessageReceiver receiver = getReceiver(socket, crypt);
		receiver.receiveMessage();
		String serviceIdentity = receiver.getItem("identity");
		
		return serviceIdentity.equals(service);
	}
	
	private void sendHandshakeRequest(Socket socket, String identity, SecretKey sessionKey, String serviceTicket){
		MessageSender sender = getSender(socket, crypt);
		sender.addItem("ticket", serviceTicket);
		sender.addItem("authenticator", getAuthenticator(identity, sessionKey));
		sender.sendMessage();
	}
	
	private String getAuthenticator(String identity, SecretKey sessionKey){
		Authenticator authenticator = new Authenticator();
		authenticator.identity = identity;
		authenticator.timestamp = System.currentTimeMillis() / 1000;
		String json = authenticator.getJson().getAsString();
		byte[] cipher = crypt.encryptMessage(sessionKey, json);
		return crypt.encode(cipher);
	}
	
	private MessageReceiver requestTicket(String identity, SecretKey secretKey, String service){
		Socket socket = new Socket(); 
		try {
			socket.connect(new InetSocketAddress("auth.spinalcraft.com", 9494), 5000);
			MessageSender sender = getSender(socket, crypt);
			sender.addHeader("identity", identity);
			sender.addHeader("intent", "ticket");
			sender.addItem("service", service);
			sender.sendMessage();
			
			MessageReceiver receiver = getReceiver(socket, crypt);
			receiver.receiveMessage();
			socket.close();
			return receiver;
			
//			String clientTicketCipher = receiver.getItem("clientTicket");
//			ClientTicket clientTicket = ClientTicket.fromCipher(clientTicketCipher, secretKey);
//			if(clientTicket == null)
//				return null;
//			
//			String serviceTicketCipher = receiver.getItem("serviceTicket");
//			cacheTicket(service, serviceTicketCipher);
//
//			return serviceTicketCipher;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private String extractServiceTicket(MessageReceiver receiver, String service){
		String serviceTicketCipher = receiver.getItem("serviceTicket");
		cacheTicket(service, serviceTicketCipher);

		return serviceTicketCipher;
	}
	
	private ClientTicket extractClientTicket(MessageReceiver receiver, SecretKey secretKey){
		String clientTicketCipher = receiver.getItem("clientTicket");
		return ClientTicket.fromCipher(clientTicketCipher, secretKey, crypt);
	}
	
	private String getHash(String username, String password){
		MessageDigest md;
		String str = username + "spinalcraft" + password;
		try {
			md = MessageDigest.getInstance("SHA-256");

			md.update(str.getBytes("UTF-8"));
			byte[] digest = md.digest();
			return crypt.encode(digest);
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	protected abstract void cacheSessionKey(String service, String sessionKey);
	
	protected abstract String retrieveSessionKey(String service);
	
	protected abstract void cacheTicket(String service, String ticket);
	
	protected abstract String retrieveTicket(String service);
}
