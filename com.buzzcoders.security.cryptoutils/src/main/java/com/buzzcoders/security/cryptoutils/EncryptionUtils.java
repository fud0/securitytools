/*******************************************************************************
 * Copyright (c) 2014 Buzzcoders.com.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * Contributors:
 *     Massimo Rabbi - initial API and implementation
 ******************************************************************************/
package com.buzzcoders.security.cryptoutils;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.buzzcoders.security.cryptoutils.asymmetric.AsymmetricEncryptionModule;
import com.buzzcoders.security.cryptoutils.asymmetric.RSAEncryptionModule;

/**
 * Utility class to manage encryption related operations.
 * 
 * @author Massimo Rabbi (mrabbi@users.sourceforge.net)
 *
 */
public final class EncryptionUtils {
	
	private static final Logger LOG = LoggerFactory.getLogger(EncryptionUtils.class);
	
	public static final int KEY_LENGTH_256=256;
	public static final int KEY_LENGTH_512=512;
	public static final int KEY_LENGTH_1024=1024;
	public static final int KEY_LENGTH_2048=2048;
	public static final int KEY_LENGTH_4096=4096;
	
	public static final String RSA_ALGORITHM="RSA";
	
	public static final Map<String,AsymmetricEncryptionModule> encryptionModules;
	
	static {
		encryptionModules=new HashMap<String, AsymmetricEncryptionModule>(1);
		encryptionModules.put(RSA_ALGORITHM, RSAEncryptionModule.getInstance());
	}

	/**
	 * 
	 * @param algorithm the algorithm
	 * @return
	 */
	public static AsymmetricEncryptionModule getEncryptionModule(String algorithm) {
		AsymmetricEncryptionModule module = encryptionModules.get(algorithm);
		if(module!=null){
			return module;
		}
		throw new UnsupportedOperationException("No encryption module is registered for this algorithm");
	}
	
	public static Key getPublicKey(KeyPair kp) {
		return (kp!=null) ? kp.getPublic() : null;
	}
	
	public static Key getPrivateKey(KeyPair kp) {
		return (kp!=null) ? kp.getPrivate() : null;
	}
	
	// just testing...
	public static void main(String[] args){
		String message="This is a simple test message";
		LOG.info("CLEAR TEXT: " + message);
		
		for(AsymmetricEncryptionModule encModule : encryptionModules.values()) {
			LOG.info(MessageFormat.format("USING {0} Algorithm",encModule.getAlgorithm()));
			String privKeyPath = "/tmp/"+encModule.getAlgorithm()+"private.key";
			String pubKeyPath = "/tmp/"+encModule.getAlgorithm()+"public.key";
			KeyPair kp = encModule.generateKeyPair(KEY_LENGTH_1024);
			byte[] encryptedInMemory = encModule.encryptData(kp.getPublic(), message.getBytes());
			byte[] clearInMemory = encModule.decryptData(kp.getPrivate(), encryptedInMemory);
			LOG.info("DECRYPTED TEXT -- memory: " + new String(clearInMemory));
			encModule.storePrivateKey(privKeyPath, kp.getPrivate());
			encModule.storePublicKey(pubKeyPath, kp.getPublic());
			PrivateKey privKey = encModule.loadPrivateKey(privKeyPath);
			PublicKey pubKey = encModule.loadPublicKey(pubKeyPath);
			byte[] encryptedFS = encModule.encryptData(pubKey, message.getBytes());
			byte[] decryptedFS = encModule.decryptData(privKey, encryptedFS);
			LOG.info("DECRIPTED TEXT -- filesystem: " + new String(decryptedFS));
		}
	}
}
