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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import org.hibernate.annotations.GenericGenerator;

import com.daon.identityx.controller.model.CreateAccount;
import com.fasterxml.jackson.annotation.JsonIgnore;

/***
 * The class to represent an account.
 * 
 * @author Daon
 *
 */
@Entity
public class Account {

    @Id
	@GeneratedValue(generator="idGenerator")
	@GenericGenerator(name="idGenerator", strategy="com.daon.identityx.utils.IdGenerator")
    private String id;
    private String firstName;
    private String lastName;
    @Column(unique = true, columnDefinition="VARCHAR_IGNORECASE(255)") 
    private String email;
    @JsonIgnore
    private byte[] hashedPassword;
    private int iterations;
    private byte[] salt;
    private Timestamp lastLoggedIn;
    private String idXId;
    
    private Timestamp createdDTM;

    protected Account() {
    	
    }

    public Account(CreateAccount createUser) {
        this.firstName = createUser.getFirstName();
        this.lastName = createUser.getLastName();
        this.email = createUser.getEmail();
        this.createdDTM = new Timestamp(System.currentTimeMillis());
    }

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public Timestamp getCreatedDTM() {
		return createdDTM;
	}

	public void setCreatedDTM(Timestamp createdDTM) {
		this.createdDTM = createdDTM;
	}

	public int getIterations() {
		return iterations;
	}

	public void setIterations(int iterations) {
		this.iterations = iterations;
	}

	public byte[] getSalt() {
		return salt;
	}

	public void setSalt(byte[] salt) {
		this.salt = salt;
	}

	public byte[] getHashedPassword() {
		return hashedPassword;
	}

	public void setHashedPassword(byte[] hashedPassword) {
		this.hashedPassword = hashedPassword;
	}

	public Timestamp getLastLoggedIn() {
		return lastLoggedIn;
	}

	public void setLastLoggedIn(Timestamp lastLoggedIn) {
		this.lastLoggedIn = lastLoggedIn;
	}

	public String getIdXId() {
		return idXId;
	}

	public void setIdXId(String idXId) {
		this.idXId = idXId;
	}

}