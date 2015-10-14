package com.spinalcraft.berberos.client;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import com.spinalcraft.berberos.common.Authenticator;
import com.spinalcraft.berberos.common.BerberosEntity;
import com.spinalcraft.easycrypt.EasyCrypt;
import com.spinalcraft.easycrypt.messenger.MessageReceiver;
import com.spinalcraft.easycrypt.messenger.MessageSender;

public abstract class BerberosClient extends BerberosEntity{
	protected EasyCrypt crypt;
	protected boolean cacheTickets = true;
	
	public BerberosClient(EasyCrypt crypt){
		this.crypt = crypt;
	}
	
	public ClientAmbassador getAmbassador(Socket socket, String username, String password, String service){
		AccessPackage accessPackage = null;
		
		if(cacheTickets){
			accessPackage = loadCachedAccessPackage(service);
		}
		
		if(accessPackage == null)
			accessPackage = getAccessFromAuthServer(socket, username, password, service);
		
		if(accessPackage == null)
			return null;
		
		return performHandshake(socket, username, password, accessPackage, service);
	}
	
	public boolean testCredentials(String username, String password){
		Socket socket = new Socket();
		try {
			socket.connect(new InetSocketAddress("auth.spinalcraft.com", 9494), 5000);
			MessageSender sender = getSender(socket, crypt);
			sender.addHeader("identity", username);
			sender.addHeader("intent", "testCredentials");
			sender.sendMessage();
			MessageReceiver receiver = getReceiver(socket, crypt);
			if(!receiver.receiveMessage())
				return false;
			socket.close();
			if(receiver.getHeader("status").equals("bad"))
				return false;
			String authCipher = receiver.getItem("authenticator");
			Authenticator authenticator = Authenticator.fromCipher(authCipher, getSecretKey(username, password), crypt);
			if(authenticator == null)
				return false;
			if(!authenticator.identity.equals("Berberos"))
				return false;
			return true;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	}
	
	private AccessPackage getAccessFromAuthServer(Socket socket, String username, String password, String service){
		AccessPackage accessPackage = new AccessPackage();
		SecretKey secretKey = getSecretKey(username, password);
		
		MessageReceiver receiver = requestTicket(username, secretKey, service);
		if(receiver == null || receiver.getHeader("status") == null || receiver.getHeader("status").equals("bad"))
			return null;
		accessPackage.serviceTicket = extractServiceTicket(receiver, service);
		ClientTicket clientTicket = extractClientTicket(receiver, secretKey);
		accessPackage.sessionKey = clientTicket.sessionKey;
		if(cacheTickets){
			cacheTicket(service, receiver.getItem("serviceTicket"));
			cacheSessionKey(service, crypt.stringFromSecretKey(accessPackage.sessionKey));
		}
		return accessPackage;
	}
	
	private AccessPackage loadCachedAccessPackage(String service){
		AccessPackage accessPackage = new AccessPackage();
		accessPackage.serviceTicket = retrieveTicket(service);
		String sessionKeyString = retrieveSessionKey(service);
		if(sessionKeyString == null || accessPackage.serviceTicket == null)
			return null;
		accessPackage.sessionKey = crypt.loadSecretKey(sessionKeyString);
		return accessPackage;
	}
	
	private ClientAmbassador performHandshake(Socket socket, String username, String password, AccessPackage accessPackage, String service){
		sendHandshakeRequest(socket, username, accessPackage.sessionKey, accessPackage.serviceTicket);
		return receiveHandshakeResponse(socket, username, password, accessPackage.sessionKey, service);
	}
	
	private ClientAmbassador receiveHandshakeResponse(Socket socket, String username, String password, SecretKey sessionKey, String service){
		MessageReceiver receiver = getReceiver(socket, crypt);
		receiver.receiveMessage();
		if(receiver.getHeader("status") != null && receiver.getHeader("status").equals("bad")){
			if(receiver.getItem("reason") != null && receiver.getItem("reason").equals("ticketExpired")){
				AccessPackage accessPackage = getAccessFromAuthServer(socket, username, password, service);
				if(accessPackage == null)
					return null;
				return performHandshake(socket, username, password, accessPackage, service);
			}
			else{
				return null;
			}
		}
		String authenticatorCipher = receiver.getItem("authenticator");
		Authenticator authenticator = Authenticator.fromCipher(authenticatorCipher, sessionKey, crypt);
		if(authenticator == null)
			return null;
		
		if(!authenticator.identity.equals(service))
			return null;
		return new ClientAmbassador(socket, sessionKey, crypt, this);
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
		String json = authenticator.getJson().toString();
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
			if(!receiver.receiveMessage())
				return null;
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

		return serviceTicketCipher;
	}
	
	private ClientTicket extractClientTicket(MessageReceiver receiver, SecretKey secretKey){
		String clientTicketCipher = receiver.getItem("clientTicket");
		return ClientTicket.fromCipher(clientTicketCipher, secretKey, crypt);
	}
	
	private SecretKey getSecretKey(String username, String password){
		String hash = getHash(username, password);
		return crypt.loadSecretKey(hash);
	}
	
	private String getHash(String username, String password){
		MessageDigest md;
		String str = username + "spinalcraft" + password;
		try {
			md = MessageDigest.getInstance("SHA-256");

			md.update(str.getBytes());
			byte[] digest = md.digest();
			return bytesToHex(digest);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte byt : bytes) result.append(Integer.toString((byt & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
	
	protected abstract void cacheSessionKey(String service, String sessionKey);
	
	protected abstract String retrieveSessionKey(String service);
	
	protected abstract void cacheTicket(String service, String ticket);
	
	protected abstract String retrieveTicket(String service);
}
