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

package com.daon.identityx.fido;

import com.daon.identityx.rest.model.pojo.RegistrationChallenge;

/***
 * Class used to hold a FIDO registration challenge and the IdentityX ID.
 * This is used when an account is created to return all the data to the 
 * REST layer from a single operation on the IdentityX service interface.
 *  
 * @author Daon
 *
 */
public class FIDORegChallengeAndId {

	private String idXId;
	private RegistrationChallenge registrationChallenge;
	
	public FIDORegChallengeAndId() {
	}

	public String getIdXId() {
		return idXId;
	}

	public void setIdXId(String idXId) {
		this.idXId = idXId;
	}

	public RegistrationChallenge getRegistrationChallenge() {
		return registrationChallenge;
	}

	public void setRegistrationChallenge(RegistrationChallenge registrationChallenge) {
		this.registrationChallenge = registrationChallenge;
	}

}
