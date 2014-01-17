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
package com.buzzcoders.security.cryptoutils.asymmetric;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This interface exposes all the methods that a module for asymmetric
 * cryptography should have.
 * 
 * @author Massimo Rabbi (mrabbi@users.sourceforge.net)
 * 
 */
public interface AsymmetricEncryptionModule {

	/**
	 * @return the encryption algorithm used in the module
	 */
	String getAlgorithm();

	/**
	 * Generates a {@link KeyPair} instance, a public key and a private key.
	 * 
	 * @param keyLength
	 *            the key length
	 * @return the key pair generated
	 */
	KeyPair generateKeyPair(int keyLength);

	/**
	 * Persists the input public key to the specified location.
	 * 
	 * @param path
	 *            the output path of the public key
	 * @param publicKey
	 *            the key to save
	 */
	void storePublicKey(String path, PublicKey publicKey);

	/**
	 * Persists the input private key to the specified location.
	 * 
	 * @param path
	 *            the output path of the private key
	 * @param privateKey
	 *            the key to save
	 */
	void storePrivateKey(String path, PrivateKey privateKey);

	/**
	 * Loads the public key from the specified location.
	 * 
	 * @param path
	 *            the input path of the public key
	 * @return the loaded key instance
	 */
	PublicKey loadPublicKey(String path);

	/**
	 * Loads the private key from the specified location.
	 * 
	 * @param path
	 *            the input path of the private key
	 * @return the loaded key instance
	 */
	PrivateKey loadPrivateKey(String path);

	/**
	 * Encrypts a block of data using the specified input public key.
	 * 
	 * @param publicKey
	 *            the public key to encrypt
	 * @param data
	 *            the clear text data to encrypt
	 * @return the encrypted data
	 */
	byte[] encryptData(PublicKey publicKey, byte[] data);

	/**
	 * Decrypts a block of data using the specified input private key.
	 * 
	 * @param privateKey
	 *            the private key to decrypt
	 * @param data
	 *            the crypted data to decrypt
	 * @return the clear text data
	 */
	byte[] decryptData(PrivateKey privateKey, byte[] encryptedData);

}
