/*
* Copyright Daon.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package com.daon.identityx.utils;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SessionImplementor;
import org.hibernate.id.IdentifierGenerator;
import org.hibernate.service.spi.Configurable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/***
 * Generates the unique ID for the rows within a database table
 * Uses a GUID rather than having to ask the DB to manage it
 * 
 * @author Daon
 *
 */
public class IdGenerator implements IdentifierGenerator, Configurable {

	private static final Logger logger = LoggerFactory.getLogger(IdGenerator.class);
	
	private SecureRandom secureRandom = new SecureRandom();
	
	public IdGenerator() {
	}

    public synchronized Serializable generate(SessionImplementor session, Object obj) throws HibernateException {

    	byte[] keyBytes = new byte[16];
    	this.getSecureRandom().nextBytes(keyBytes);
    	String key = Base64.getUrlEncoder().encodeToString(keyBytes);
    	key = key.substring(0,22);
    	logger.trace("Next key will be: {}", key);
        return key;
    }
 
	@SuppressWarnings("rawtypes")
	@Override
	public void configure(Map configurationValues) {
		
    	logger.debug("Configuring the new instance of the RandomUUIDSequenceGenerator");
	}

	public SecureRandom getSecureRandom() {
		return secureRandom;
	}

	public void setSecureRandom(SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}
}