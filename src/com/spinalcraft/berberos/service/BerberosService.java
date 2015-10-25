package com.spinalcraft.berberos.service;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import javax.crypto.SecretKey;
import com.spinalcraft.berberos.common.Authenticator;
import com.spinalcraft.berberos.common.BerberosEntity;
import com.spinalcraft.easycrypt.EasyCrypt;
import com.spinalcraft.easycrypt.messenger.MessageReceiver;
import com.spinalcraft.easycrypt.messenger.MessageSender;

public abstract class BerberosService extends BerberosEntity{
	private String identity;
	private String serviceAddress;
	private int servicePort;
	private SecretKey secretKey;
	private EasyCrypt crypt;
	
	public BerberosService(EasyCrypt crypt){
		this.crypt = crypt;
	}
	
	public BerberosService setIdentity(String identity){
		this.identity = identity;
		return this;
	}
	
	public BerberosService setServiceAddress(String address){
		this.serviceAddress = address;
		return this;
	}
	
	public BerberosService setPort(int port){
		this.servicePort = port;
		return this;
	}
	
	public boolean init(String address, int port, String accessKey){
		String secretKeyString = retrieveSecretKey();
		if(secretKeyString != null)
			secretKey = crypt.loadSecretKey(secretKeyString);
		else{
			secretKey = register(address, port, accessKey);
			if(secretKey == null)
				return false;
		}
		return true;
	}
	
	public String getIdentity(){
		return identity;
	}
	
	private SecretKey register(String address, int port, String accessKey){
		Socket socket = new Socket();
		try {
			KeyPair keyPair = crypt.generateKeys();
			socket.setSoTimeout(5000);
			socket.connect(new InetSocketAddress(address, port), 5000);
			MessageSender sender = getSender(socket, crypt);
			sender.addHeader("intent", "registerService");
			sender.addItem("identity", identity);
			sender.addItem("publicKey", crypt.stringFromPublicKey(keyPair.getPublic()));
			sender.addItem("serviceAddress", serviceAddress);
			sender.addItem("servicePort", Integer.toString(servicePort));
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
		
		if(authenticatorCached(authCipher)){
			System.err.println("Duplicate authenticator detected. I/O error or possible replay attempt!");
			return null;
		}
		
		ServiceTicket ticket = ServiceTicket.fromCipher(ticketCipher, secretKey, crypt);
		if(ticket == null){
			return null;
		}
		
		Authenticator authenticator = Authenticator.fromCipher(authCipher, ticket.sessionKey, crypt);
		
		if(!validTicket(ticket)){
			System.out.println("Ticket was expired.");
			notifyOfExpiredTicket(socket);
			return getAmbassador(socket);
		}
		
		if(validAuthenticator(authenticator, ticket) && cacheAuthenticator(authCipher))
			return new ServiceAmbassador(socket, ticket.sessionKey, crypt, this);
		System.err.println("Ticket or authenticator was invalid.");
		return null;
	}
	
	protected abstract boolean authenticatorCached(String authenticator);
	
	protected abstract boolean cacheAuthenticator(String authenticator);
	
	private void notifyOfExpiredTicket(Socket socket){
		MessageSender sender = getSender(socket, crypt);
		sender.addHeader("status", "bad");
		sender.addItem("reason", "ticketExpired");
		sender.sendMessage();
	}
	
	private boolean validTicket(ServiceTicket ticket){
		System.out.println("Expiration: " + ticket.expiration);
		System.out.println("Current time: " + System.currentTimeMillis() / 1000);
		return ticket.expiration > System.currentTimeMillis() / 1000;
	}
	
	private boolean validAuthenticator(Authenticator authenticator, ServiceTicket ticket){
		return authenticator.identity.equals(ticket.clientIdentity);
	}
	
	protected abstract void storeSecretKey(String secretKey);
	
	protected abstract String retrieveSecretKey();
}
