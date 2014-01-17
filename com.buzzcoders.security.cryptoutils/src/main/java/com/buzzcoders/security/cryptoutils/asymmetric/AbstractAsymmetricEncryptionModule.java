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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An abstract implementation of an asymmetric encryption module.
 * It contains all the shared methods that can be later re-used in the specialized modules.
 * 
 * @author Massimo Rabbi (mrabbi@users.sourceforge.net)
 *
 */
public abstract class AbstractAsymmetricEncryptionModule implements	AsymmetricEncryptionModule {
	
	private static final Logger LOG = LoggerFactory.getLogger(AbstractAsymmetricEncryptionModule.class);
	
	/*
	 * (non-Javadoc)
	 * @see com.buzzcoders.security.cryptoutils.asymmetric.AsymmetricEncryptionModule#generateKeyPair(int)
	 */
	public KeyPair generateKeyPair(int keyLength) {
		KeyPair kp = null;
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(getAlgorithm());
			kpg.initialize(keyLength);
			kp = kpg.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			LOG.error("Error generating the key pair.",e);
		}
		return kp;
	}

	/*
	 * (non-Javadoc)
	 * @see com.buzzcoders.security.cryptoutils.asymmetric.AsymmetricEncryptionModule#storePublicKey(java.lang.String, java.security.PublicKey)
	 */
	public void storePublicKey(String path, PublicKey publicKey) {
		FileOutputStream fos = null;
		try {
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
			fos= new FileOutputStream(path);
			fos.write(x509EncodedKeySpec.getEncoded());
		} catch (FileNotFoundException e) {
			LOG.error("Cannot save the public key to the specified path.",e);
		} catch (IOException e) {
			LOG.error("An I/O error occured while saving the public key",e);
		} finally {
			IOUtils.closeQuietly(fos);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see com.buzzcoders.security.cryptoutils.asymmetric.AsymmetricEncryptionModule#storePrivateKey(java.lang.String, java.security.PrivateKey)
	 */
	public void storePrivateKey(String path, PrivateKey privateKey) {
		FileOutputStream fos = null;
		try {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
					privateKey.getEncoded());
			fos = new FileOutputStream(path);
			fos.write(pkcs8EncodedKeySpec.getEncoded());
		} catch (FileNotFoundException e) {
			LOG.error("Cannot save the private key to the specified path.",e);
		} catch (IOException e) {
			LOG.error("An I/O error occured while saving the private key",e);
		} finally { 
			IOUtils.closeQuietly(fos);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see com.buzzcoders.security.cryptoutils.asymmetric.AsymmetricEncryptionModule#loadPublicKey(java.lang.String)
	 */
	public PublicKey loadPublicKey(String path) {
		FileInputStream fis = null;
		try {
			File filePublicKey = new File(path);
			fis = new FileInputStream(path);
			byte[] pubKey = new byte[(int) filePublicKey.length()];
			fis.read(pubKey);
			KeyFactory keyFactory = KeyFactory.getInstance(getAlgorithm());
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKey);
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			return publicKey;
		} catch (Exception e){
			LOG.error("An error occurred while loading the public key from disk.",e);
		} finally {
			IOUtils.closeQuietly(fis);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * @see com.buzzcoders.security.cryptoutils.asymmetric.AsymmetricEncryptionModule#loadPrivateKey(java.lang.String)
	 */
	public PrivateKey loadPrivateKey(String path) {
		FileInputStream fis = null;
		try {
			File filePrivateKey = new File(path);
			fis = new FileInputStream(path);
			byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
			fis.read(encodedPrivateKey);
			KeyFactory keyFactory = KeyFactory.getInstance(getAlgorithm());
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
					encodedPrivateKey);
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			return privateKey;
		} catch (Exception e) {
			LOG.error("An error occurred while loading the private key from disk.",e);
		} finally {
			IOUtils.closeQuietly(fis);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * @see com.buzzcoders.security.cryptoutils.asymmetric.AsymmetricEncryptionModule#encryptData(java.security.PublicKey, byte[])
	 */
	public byte[] encryptData(PublicKey publicKey, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance(getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(data);
		} catch (Exception e) {
			LOG.error("An error occurred while encrypting the input data.",e);
		}
		return new byte[0];
	}

	/*
	 * (non-Javadoc)
	 * @see com.buzzcoders.security.cryptoutils.asymmetric.AsymmetricEncryptionModule#decryptData(java.security.PrivateKey, byte[])
	 */
	public byte[] decryptData(PrivateKey privateKey, byte[] encryptedData) {
		try {
			Cipher cipher = Cipher.getInstance(getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return cipher.doFinal(encryptedData);
		} catch (Exception e) {
			LOG.error("An error occurred while decrypting the input data.",e);
		}
		return new byte[0];
	}

}
