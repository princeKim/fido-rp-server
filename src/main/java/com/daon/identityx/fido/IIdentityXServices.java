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

import com.daon.identityx.controller.model.AuthenticatorInfo;
import com.daon.identityx.controller.model.PolicyInfo;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.daon.identityx.rest.model.pojo.FIDOFacets;
import com.daon.identityx.rest.model.pojo.RegistrationChallenge;

/***
 * The interface through which all the operations on IdentityX are performed.
 * 
 * @author Daon
 *
 */
public interface IIdentityXServices {

	/**
	 * Retrieves the registration policy information.
	 * @return
	 */
	public PolicyInfo getRegistrationPolicyInfo();

	/**
	 * Retrieves the authentication policy information.
	 * @return
	 */
	public PolicyInfo getAuthenticationPolicyInfo();

	/***
	 * Create the FIDO registration request for the user
	 * 
	 * @param userId
	 * @return
	 */
	public FIDORegChallengeAndId createRegRequest(String email, String idxId);

	/***
	 * Process the FIDO registration response as provided
	 * 
	 * @param idxId
	 * @param registrationChallengeHref
	 * @param fidoRegChallengeResponse
	 * @return
	 */
	public RegistrationChallenge processRegistrationResponse(String idxId, String registrationChallengeHref, String fidoRegChallengeResponse);

	/***
	 * Delete the user with the specified identifier
	 * 
	 * @param idxId
	 */
	public void deleteUser(String idxId);

	/***
	 * Create a FIDO authentication request to be sent to the FIDO client
	 * 
	 * @return
	 */
	public AuthenticationRequest createAuthRequest();

	/***
	 * Validate the authentication response from the FIDO client
	 * 
	 * @param authenticationRequestHref
	 * @param authResponse
	 * @return
	 */
	public AuthenticationRequest validateAuthResponse(String authenticationRequestHref, String authResponse);

	/***
	 * Get the FIDO Facets for the application which can be returned to the FIDO Client
	 * 
	 * @return
	 */
	public FIDOFacets getFidoFacets();

	/***
	 * Get a list of FIDO Authenticators for this user
	 *   The list of authenticators does NOT contain the fidoDeregistrationRequest
	 * 
	 * @param idxId
	 * @return
	 */
	public AuthenticatorInfo[] listAuthenticators(String idxId);


	/***
	 * Gets all the details of the specified FIDO Authenticator.
	 * Also ensures that the id of the authenticator relates to the user whose id
	 * is supplied.  
	 * Getting the details of the authenticator will return the fidoDeregistrationRequest
	 *  
	 * @param idxId
	 * @param id
	 * @return
	 */
	public AuthenticatorInfo getAuthenticator(String idxId, String id);

	/***
	 * Deletes/deactivate the specified authenticator and returns the fidoDeregistrationRequest.
	 * Also ensures that the id of the authenticator relates to the user whose id
	 * is supplied. 
	 * 
	 * @param idxId
	 * @param authenticatorId
	 * @return
	 */
	public String deleteAuthenticator(String idxId, String authenticatorId);

	/***
	 * Creates a FIDO transaction confirmation for the user whose ID is supplied.
	 * The transactionContentType can be
	 * 		
	 *  
	 * @param idxId
	 * @param transactionContentType
	 * @param transactionContent
	 * @param stepUpAuth
	 * @return
	 */
	public AuthenticationRequest createAuthTransactionRequest(String idxId, String transactionContentType, String transactionContent,
			boolean stepUpAuth);
	
	/***
	 * Deactivates all the FIDO authenticators associated with the user and then
	 * deletes/deactivates the user whose id is supplied.  
	 * 
	 * @param idxId
	 * @return
	 */
	public AuthenticatorInfo[] deactivateAndDelete(String idxId);
}
