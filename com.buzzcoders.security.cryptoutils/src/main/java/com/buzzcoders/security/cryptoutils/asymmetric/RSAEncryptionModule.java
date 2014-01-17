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

import com.buzzcoders.security.cryptoutils.EncryptionUtils;


/**
 * The module for RSA algorithm encryption.
 * 
 * @author Massimo Rabbi (mrabbi@users.sourceforge.net)
 *
 */
public final class RSAEncryptionModule extends AbstractAsymmetricEncryptionModule {

	private static final RSAEncryptionModule INSTANCE = new RSAEncryptionModule();
	
	private RSAEncryptionModule(){
		super();
	}
	
	public String getAlgorithm() {
		return EncryptionUtils.RSA_ALGORITHM;
	}

	public static AsymmetricEncryptionModule getInstance() {
		return INSTANCE;
	}

}
