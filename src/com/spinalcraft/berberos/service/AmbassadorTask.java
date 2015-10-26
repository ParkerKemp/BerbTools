package com.spinalcraft.berberos.service;

import java.net.Socket;

import javax.crypto.SecretKey;

import com.spinalcraft.berberos.common.Authenticator;
import com.spinalcraft.easycrypt.EasyCrypt;
import com.spinalcraft.easycrypt.messenger.MessageReceiver;
import com.spinalcraft.easycrypt.messenger.MessageSender;

public class AmbassadorTask implements Runnable{
	
	private BerberosService service;
	private Socket socket;
	private SecretKey secretKey;
	private EasyCrypt crypt;

	public AmbassadorTask(BerberosService service, Socket socket, SecretKey secretKey, EasyCrypt crypt) {
		this.service = service;
		this.socket = socket;
		this.secretKey = secretKey;
		this.crypt = crypt;		
	}
	
	@Override
	public void run() {
		ServiceAmbassador ambassador = getAmbassador();
		if(ambassador != null)
			service.onAuthenticated(ambassador);
	}
	
	private ServiceAmbassador getAmbassador(){
		System.out.println("Accepted socket");
		MessageReceiver receiver = service.getReceiver(socket, crypt);
		System.out.println("Waiting on message.");
		receiver.receiveMessage();
		System.out.println("Received message.");
		String ticketCipher = receiver.getItem("ticket");
		String authCipher = receiver.getItem("authenticator");
		if(ticketCipher == null || authCipher == null){
			sendDenial(socket);
			return null;
		}
		
		if(service.authenticatorCached(authCipher)){
			System.err.println("Duplicate authenticator detected. I/O error or possible replay attempt!");
			return null;
		}
		
		ServiceTicket ticket = ServiceTicket.fromCipher(ticketCipher, secretKey, crypt);
		if(ticket == null){
			return null;
		}
		
		Authenticator authenticator = Authenticator.fromCipher(authCipher, ticket.sessionKey, crypt);
		
		if(!validTicket(ticket)){
			notifyOfExpiredTicket(socket);
			return getAmbassador();
		}
		
		if(validAuthenticator(authenticator, ticket) && service.cacheAuthenticator(authCipher))
			return new ServiceAmbassador(socket, ticket.sessionKey, crypt, service);
		System.err.println("Ticket or authenticator was invalid.");
		return null;
	}
	
	private boolean validAuthenticator(Authenticator authenticator, ServiceTicket ticket){
		return authenticator.identity.equals(ticket.clientIdentity);
	}

	private void sendDenial(Socket socket){
		MessageSender sender = service.getSender(socket, crypt);
		sender.addHeader("status", "bad");
		sender.sendMessage();
	}
	
	private void notifyOfExpiredTicket(Socket socket){
		MessageSender sender = service.getSender(socket, crypt);
		sender.addHeader("status", "bad");
		sender.addItem("reason", "ticketExpired");
		sender.sendMessage();
	}
	
	private boolean validTicket(ServiceTicket ticket){
		System.out.println("Expiration: " + ticket.expiration);
		System.out.println("Current time: " + System.currentTimeMillis() / 1000);
		return ticket.expiration > System.currentTimeMillis() / 1000;
	}

}
