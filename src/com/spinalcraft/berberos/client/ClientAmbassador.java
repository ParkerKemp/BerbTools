package com.spinalcraft.berberos.client;

import java.net.Socket;

import javax.crypto.SecretKey;

import com.spinalcraft.berberos.common.Ambassador;
import com.spinalcraft.berberos.common.BerberosEntity;
import com.spinalcraft.easycrypt.EasyCrypt;
import com.spinalcraft.easycrypt.messenger.MessageSender;

public class ClientAmbassador extends Ambassador{
	
	private String identity;

	public ClientAmbassador(Socket socket, SecretKey sessionKey, EasyCrypt crypt, BerberosEntity entity, String identity) {
		super(socket, sessionKey, crypt, entity);
		this.identity = identity;
	}
	
	public boolean sendMessage(MessageSender sender){
		sender.addHeader("identity", identity);
		return super.sendMessage(sender);
	}
}
