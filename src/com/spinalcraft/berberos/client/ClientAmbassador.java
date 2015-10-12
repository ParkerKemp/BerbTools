package com.spinalcraft.berberos.client;

import java.net.Socket;

import javax.crypto.SecretKey;

import com.spinalcraft.berberos.common.Ambassador;
import com.spinalcraft.berberos.common.BerberosEntity;
import com.spinalcraft.easycrypt.EasyCrypt;

public class ClientAmbassador extends Ambassador{

	public ClientAmbassador(Socket socket, SecretKey sessionKey, EasyCrypt crypt, BerberosEntity entity) {
		super(socket, sessionKey, crypt, entity);
	}
}
