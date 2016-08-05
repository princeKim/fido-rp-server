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

package com.daon.identityx.entity;

import java.sql.Timestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import org.hibernate.annotations.GenericGenerator;
import org.springframework.beans.factory.annotation.Value;

/***
 * This class represents a session with the app.
 * 
 * @author Daon
 *
 */
@Entity
public class Session {

	public static final long DEFAULT_SESSION_PERIOD = 1000*900;
		
    @Id
	@GeneratedValue(generator="idGenerator")
	@GenericGenerator(name="idGenerator", strategy="com.daon.identityx.utils.IdGenerator")
    private String id;
    private String accountId;
    private Timestamp createdDTM;
    private Timestamp expiringDTM;

    public Session(Account user, long sessionPeriod) {
    	this.accountId = user.getId();
    	this.createdDTM = new Timestamp(System.currentTimeMillis());
    	this.expiringDTM = new Timestamp(System.currentTimeMillis() + sessionPeriod);
    }
    
    public Session() {
    }

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getAccountId() {
		return accountId;
	}

	public void setAccountId(String userId) {
		this.accountId = userId;
	}

	public Timestamp getCreatedDTM() {
		return createdDTM;
	}

	public void setCreatedDTM(Timestamp createdDTM) {
		this.createdDTM = createdDTM;
	}

	public Timestamp getExpiringDTM() {
		return expiringDTM;
	}

	public void setExpiringDTM(Timestamp expiringDTM) {
		this.expiringDTM = expiringDTM;
	}


}