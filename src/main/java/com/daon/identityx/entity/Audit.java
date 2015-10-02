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

/***
 * A simple audit record - each REST interaction is recorded in the database with an Audit record.
 * 
 * @author Daon
 *
 */
@Entity
public class Audit {

    @Id
	@GeneratedValue(generator="idGenerator")
	@GenericGenerator(name="idGenerator", strategy="com.daon.identityx.utils.IdGenerator")
    private String id;
    private AuditAction operation;
    private String accountId;
    private String sessionId;
    private long duration;
    private Timestamp createdDTM;

    public Audit() {
    	
    }
    
    public Audit(AuditAction anAction) {
    	
    	this.operation = anAction;
    	this.createdDTM = new Timestamp(System.currentTimeMillis());
    }
    

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public AuditAction getOperation() {
		return operation;
	}

	public void setOperation(AuditAction operation) {
		this.operation = operation;
	}

	public String getAccountId() {
		return accountId;
	}

	public void setAccountId(String userId) {
		this.accountId = userId;
	}

	public String getSessionId() {
		return sessionId;
	}

	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
	}

	public long getDuration() {
		return duration;
	}

	public void setDuration(long duration) {
		this.duration = duration;
	}

	public Timestamp getCreatedDTM() {
		return createdDTM;
	}

	public void setCreatedDTM(Timestamp createdDTM) {
		this.createdDTM = createdDTM;
	}


}