package com.spinalcraft.berberos.service;

import java.io.IOException;
import java.net.ServerSocket;
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
	private ServerSocket serverSocket;
	
	public BerberosService(String berberosAddress, int berberosPort, EasyCrypt crypt) {
		super(berberosAddress, berberosPort, crypt);
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
	
	public boolean init(String accessKey){
		String secretKeyString = retrieveSecretKey();
		if(secretKeyString != null)
			secretKey = crypt.loadSecretKey(secretKeyString);
		else{
			secretKey = register(accessKey);
			if(secretKey == null)
				return false;
		}
		try {
			serverSocket = new ServerSocket(servicePort);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	public String getIdentity(){
		return identity;
	}
	
	private SecretKey register(String accessKey){
		Socket socket = connectTo(berberosAddress, berberosPort, 5000, 5);
		if(socket == null)
			return null;
		try {
			KeyPair keyPair = crypt.generateKeys();
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
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public ServiceAmbassador getAmbassador(){
		Socket socket;
		try {
			socket = serverSocket.accept();
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
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
			return getAmbassador();
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
