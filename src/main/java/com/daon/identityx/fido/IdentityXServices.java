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

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.stereotype.Service;

import com.daon.identityx.controller.model.AuthenticatorInfo;
import com.daon.identityx.controller.model.PolicyInfo;
import com.daon.identityx.exception.ProcessingException;
import com.daon.identityx.rest.model.def.AuthenticationRequestStatusEnum;
import com.daon.identityx.rest.model.def.AuthenticatorStatusEnum;
import com.daon.identityx.rest.model.pojo.Application;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.daon.identityx.rest.model.pojo.Authenticator;
import com.daon.identityx.rest.model.pojo.AuthenticatorType;
import com.daon.identityx.rest.model.pojo.FIDOFacets;
import com.daon.identityx.rest.model.pojo.Policy;
import com.daon.identityx.rest.model.pojo.Registration;
import com.daon.identityx.rest.model.pojo.RegistrationChallenge;
import com.daon.identityx.rest.model.pojo.User;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.ApplicationCollection;
import com.identityx.clientSDK.collections.AuthenticatorCollection;
import com.identityx.clientSDK.collections.PolicyCollection;
import com.identityx.clientSDK.collections.RegistrationCollection;
import com.identityx.clientSDK.collections.UserCollection;
import com.identityx.clientSDK.credentialsProviders.EncryptedKeyPropFileCredentialsProvider;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.ApplicationQueryHolder;
import com.identityx.clientSDK.queryHolders.AuthenticatorQueryHolder;
import com.identityx.clientSDK.queryHolders.PolicyQueryHolder;
import com.identityx.clientSDK.queryHolders.RegistrationQueryHolder;
import com.identityx.clientSDK.queryHolders.UserQueryHolder;
import com.identityx.clientSDK.repositories.ApplicationRepository;
import com.identityx.clientSDK.repositories.AuthenticationRequestRepository;
import com.identityx.clientSDK.repositories.AuthenticatorRepository;
import com.identityx.clientSDK.repositories.AuthenticatorTypeRepository;
import com.identityx.clientSDK.repositories.PolicyRepository;
import com.identityx.clientSDK.repositories.RegistrationChallengeRepository;
import com.identityx.clientSDK.repositories.RegistrationRepository;
import com.identityx.clientSDK.repositories.UserRepository;

/***
 * The class through which all interactions with IdentityX are performed.
 * 
 * @author Daon
 *
 */
@Service
@PropertySources({
	@PropertySource("classpath:fido_config.properties"),
	@PropertySource(value="file:fido_config.properties", ignoreResourceNotFound=true)
})
public class IdentityXServices implements IIdentityXServices {

	private static final Logger logger = LoggerFactory.getLogger(IdentityXServices.class);
	private static final String FIDO_AUTHENTICATION_TYPE = "FI"; 
	private static final String FIDO_AUTHENTICATOR_TYPE = "FI"; 

	@Value("${fido.application_id}")
	private String applicationId = "JamesApp1";
	@Value("${fido.reg_policy_id}")
	private String regPolicyId = "RegPolicy1";
	@Value("${fido.auth_policy_id}")
	private String authPolicyId = "AuthPolicy1";
	@Value("${fido.keystore.location}")
	private String keystoreLocation;
	@Value("${fido.keystore.password}")
	private String keystorePassword;
	@Value("${fido.keystore.keyAlias}")
	private String keystoreKeyAlias;
	@Value("${fido.keystore.keyPassword}")
	private String keystoreKeyPassword;
	@Value("${fido.credential.properties.location}")
	private String credentialPropertiesLocation;
	
	private TenantRepoFactory tenantRepoFactory;
	private Application application;
	private String regPolicyHref;
	private String authPolicyHref;
	private ObjectMapper objectMapper = new ObjectMapper();

	private final Map<String, AuthenticatorType> authenticatorTypesCache = new Hashtable<>();
	
	
	public IdentityXServices() {
	}

	@PostConstruct
	public void connectToIdentityXServer() {
		try (InputStream keyStore = new FileInputStream(new File(this.getKeystoreLocation()));
				InputStream credenitalsProperties = new FileInputStream(new File(this.getCredentialPropertiesLocation()))){
			EncryptedKeyPropFileCredentialsProvider provider = new EncryptedKeyPropFileCredentialsProvider(
					keyStore,
					this.getKeystorePassword(),
					credenitalsProperties,
					this.getKeystoreKeyAlias(),
					this.getKeystoreKeyPassword());
			tenantRepoFactory = new TenantRepoFactory(provider);
			logger.info("Connected to the IdentityX Server");
		} catch (Exception ex) {
			String error = "An exception occurred while attempting to connect to the IdentityX server.  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}

		try {
			logger.info("Attempting to find the application: {}", this.getApplicationId());
			Application anApp = this.findApplication();
			this.setApplication(anApp);
			logger.info("Found the application.");
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to find the application: " + this.getApplicationId() + ".  Exception: "
					+ ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}

		try {
			logger.info("Attempting to find the registration policy: {}", this.getRegPolicyId());
			Policy aPolicy = this.findPolicy(getRegPolicyId());
			this.setRegPolicyHref(aPolicy.getHref());
			logger.info("Found the registration policy.");
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to find the registration policy: " + this.getRegPolicyId()
					+ ".  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}

		try {
			logger.info("Attempting to find the authentication policy: {}", this.getAuthPolicyId());
			Policy aPolicy = this.findPolicy(getAuthPolicyId());
			this.setAuthPolicyHref(aPolicy.getHref());
			logger.info("Found the authentication policy.");
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to find the authentication policy: " + this.getAuthPolicyId()
					+ ".  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}

	/***
	 * Create the FIDO registration request for the user
	 * 
	 * @param userId
	 * @return
	 */
	@Override
	public FIDORegChallengeAndId createRegRequest(String email, String fidoId) {

		try {
			User user;
			if (fidoId == null) {
				user = this.findUser(email);
			} else {
				user = this.getUser(fidoId);
			}
			if (user == null) {
				user = this.addUser(email);
			}

			Registration reg = this.findRegistration(user, email);
			if (reg == null) {
				reg = this.addRegistration(user, email);
			}

			RegistrationChallenge regChallenge = this.addRegistrationChallenge(reg);
			FIDORegChallengeAndId regChallengeAndId = new FIDORegChallengeAndId();
			regChallengeAndId.setIdXId(user.getId());
			regChallengeAndId.setRegistrationChallenge(regChallenge);
			return regChallengeAndId;

		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to create the registration challenge.  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}

	/***
	 * Delete the user with the specified identifier
	 * 
	 * @param idxId
	 */
	@Override
	public void deleteUser(String fidoId) {

		if (fidoId == null) {
			logger.debug("Nothing to do - there is no user");
			return;
		}
		
		try {
			UserRepository userRepo = this.getTenantRepoFactory().getUserRepo();
			User user = new User(userRepo.getBaseUrl() + userRepo.getResourcePath() + "/" + fidoId);
			userRepo.archive(user);
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to archive the user: " + fidoId + ".  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}

	
	/***
	 * Deletes/deactivate the specified authenticator and returns the fidoDeregistrationRequest.
	 * Also ensures that the id of the authenticator relates to the user whose id
	 * is supplied. 
	 * 
	 * @param idxId
	 * @param authenticatorId
	 * @return
	 */
	@Override
	public String deleteAuthenticator(String fidoId, String authenticatorId) {
		try {
			AuthenticatorRepository authenticatorRepo = this.getTenantRepoFactory().getAuthenticatorRepo();
			Authenticator authenticator = authenticatorRepo.getById(authenticatorId);
			if (authenticator == null) {
				String error = "Unable to find the authenticator with ID: " + authenticatorId;
				logger.error(error);
				throw new RuntimeException(error);
			}
			String userId = this.getIdFromHref(authenticator.getUser().getHref());
			if (!fidoId.equals(userId)) {
				String error = "The authenticator specified does not belong to the IdentityX user with ID: " + fidoId;
				logger.error(error);
				throw new RuntimeException(error);
			}
			authenticator = authenticatorRepo.archive(authenticator);
			return authenticator.getFidoDeregistrationRequest();
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to archive the authenticator.  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}

	/***
	 * Get a list of FIDO Authenticators for this user
	 *   The list of authenticators does NOT contain the fidoDeregistrationRequest
	 * 
	 * @param idxId
	 * @return
	 */
	@Override
	public AuthenticatorInfo[] listAuthenticators(String idxId) {

		try {
			User user = this.getUser(idxId);
			if (user == null) {
				String error = "Unable to get the user with ID: " + idxId;
				logger.error(error);
				throw new RuntimeException(error);
			}

			Authenticator[] authenticators = getAuthenticators(user.getAuthenticators().getHref());

			if (authenticators == null || authenticators.length == 0) {
				return new AuthenticatorInfo[0];
			}

			// Return authenticators registered by the user which match those available on the client from which the call was made
			return convertToAuthenticatorInfo(authenticators);
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to get authenticators.  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}
	
	/***
	 * Deactivates all the FIDO authenticators associated with the user and then
	 * deletes/deactivates the user whose id is supplied.  
	 * 
	 * @param idxId
	 * @return
	 */
	@Override
	public AuthenticatorInfo[] deactivateAndDelete(String idxId) {
		
		try {
			User user = this.getUser(idxId);
			if (user == null) {
				String error = "Unable to get the user with ID: " + idxId;
				logger.error(error);
				throw new RuntimeException(error);
			}

			List<Authenticator> activeFidoAuths = getActiveFidoAuthenticators(user);
			List<Authenticator> inactiveFidoAuths = deactivateFidoAuthenticators(activeFidoAuths);
			this.addAuthenticatorTypeAAID(inactiveFidoAuths);
			Authenticator[] inactiveFidoAuthArray = inactiveFidoAuths.toArray(new Authenticator[0]);

			UserRepository userRepository = this.getTenantRepoFactory().getUserRepo();
			userRepository.archive(user);
			
			// Return authenticators registered by the user which match those available on the client from which the call was made
			return convertToAuthenticatorInfo(inactiveFidoAuthArray);
			
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to get authenticators.  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}
	
	protected AuthenticatorType getAuthenticatorType(String href) throws IdxRestException {

		if (this.getAuthenticatorTypesCache().containsKey(href)) {
			return this.getAuthenticatorTypesCache().get(href);
		} else {
			AuthenticatorTypeRepository typeRepo = this.getTenantRepoFactory().getAuthenticatorTypeRepo();
			AuthenticatorType type = typeRepo.get(href);
			this.getAuthenticatorTypesCache().put(href, type);
			return type;
		}
	}

	protected List<Authenticator> getActiveFidoAuthenticators(User user) throws IdxRestException {
		
		List<Authenticator> activeFidoAuths = new ArrayList<>();
		Authenticator[] authenticators = getAuthenticators(user.getAuthenticators().getHref());

		if (authenticators == null || authenticators.length == 0) {
			return activeFidoAuths;
		}
		for(Authenticator auth : authenticators) {
			if (auth.getStatus() == AuthenticatorStatusEnum.ARCHIVED) {
				continue;
			}
			if (!auth.getType().equals(FIDO_AUTHENTICATOR_TYPE)) {
				continue;
			}
			activeFidoAuths.add(auth);
		}
		return activeFidoAuths;
	}
	
	protected List<Authenticator> deactivateFidoAuthenticators(List<Authenticator> activeFidoAuths) throws IdxRestException {
		
		List<Authenticator> inactiveFidoAuths = new ArrayList<>();
		AuthenticatorRepository authRepo = this.getTenantRepoFactory().getAuthenticatorRepo();
		
		for(Authenticator auth : activeFidoAuths) {
			inactiveFidoAuths.add(authRepo.archive(auth));
		}
		return inactiveFidoAuths;
	}

	/***
	 * Each of the authenticators in the array has an associated AuthenticatorType but the AAID is not in the type.
	 * This method with retrieve the AuthenticatorTypes from IdentityX. 
	 * 
	 * @param activeFidoAuths
	 * @throws IdxRestException
	 */
	protected void addAuthenticatorTypeAAID(List<Authenticator> fidoAuths) throws IdxRestException {
		
		for (Authenticator auth : fidoAuths) {
			if (auth.getAuthenticatorType().getAaid() == null || auth.getAuthenticatorType().getAaid().length() == 0) {
				AuthenticatorType type = this.getAuthenticatorType(auth.getAuthenticatorType().getHref());
				auth.getAuthenticatorType().setAaid(type.getAaid());
			}
		}
	}

	
	/***
	 * Create a FIDO authentication request to be sent to the FIDO client
	 * 
	 * @return
	 */
	@Override
	public AuthenticationRequest createAuthRequest() {

		try {
			AuthenticationRequest request = new AuthenticationRequest();
			request.setPolicy(new Policy(this.getAuthPolicyHref()));
			request.setApplication(this.getApplication());
			request.setDescription("Test transaction");
			request.setType(FIDO_AUTHENTICATION_TYPE);
			request.setAuthenticationRequestId(UUID.randomUUID().toString());
			AuthenticationRequestRepository authenticationRequestRepo = this.getTenantRepoFactory().getAuthenticationRequestRepo();
			request = authenticationRequestRepo.create(request);
			logger.debug("Added an authentication request, - authRequestId: {}", request.getId());
			return request;
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to create an authentication request.  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}

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
	@Override
	public AuthenticationRequest createAuthTransactionRequest(String userId, String transactionContentType, String transactionContent,
			boolean stepUpAuth) {
		try {
			User user;
			user = this.getUser(userId);
			if (user == null) {
				String error = "Unable to find the user with ID: " + userId;
				logger.error(error);
				throw new RuntimeException(error);
			}
			AuthenticationRequest request = new AuthenticationRequest();
			request.setPolicy(new Policy(this.getAuthPolicyHref()));
			request.setApplication(this.getApplication());
			request.setDescription("Test transaction");
			request.setType(FIDO_AUTHENTICATION_TYPE);
			request.setAuthenticationRequestId(UUID.randomUUID().toString());
			request.setSecureTransactionContentType(transactionContentType);
			request.setSecureTransactionContent(transactionContent);
			if(stepUpAuth) {
				request.setUser(user);
			}
			AuthenticationRequestRepository authenticationRequestRepo = this.getTenantRepoFactory().getAuthenticationRequestRepo();
			request = authenticationRequestRepo.create(request);
			return request;
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to create an authentication transaction request.  Exception: "
					+ ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}

	/***
	 * Process the FIDO registration response as provided
	 * 
	 * @param idxId
	 * @param registrationChallengeHref
	 * @param fidoRegChallengeResponse
	 * @return
	 */
	@Override
	public RegistrationChallenge processRegistrationResponse(String idxId, String regChallengeHref, String fidoRegChallengeResponse) {

		try {
			RegistrationChallengeRepository regChallengeRepo = this.getTenantRepoFactory().getRegistrationChallengeRepo();
			RegistrationChallenge regChallenge = regChallengeRepo.get(regChallengeHref);
			if (regChallenge == null) {
				String error = "Unable to find the registration challenge with HREF: " + regChallengeHref;
				logger.error(error);
				throw new RuntimeException(error);
			}
			Registration registration = this.getRegistrationFromHref(regChallenge.getRegistration().getHref());
			String userId = this.getIdFromHref(registration.getUser().getHref());
			if (!idxId.equals(userId)){
				String error = "The registration response does not belong to the IdentityX user with ID: " + idxId
							+ " Expecting: " + idxId + " retrieved: " + userId;
				logger.error(error);
				throw new RuntimeException(error);
			}
			regChallenge.setFidoRegistrationResponse(fidoRegChallengeResponse);
			regChallenge = regChallengeRepo.update(regChallenge);

			return regChallenge;

		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to update the registration challenge.  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}

	/***
	 * Validate the authentication response from the FIDO client
	 * 
	 * @param authenticationRequestHref
	 * @param authResponse
	 * @return
	 */
	@Override
	public AuthenticationRequest validateAuthResponse(String authenticationRequestHref, String authResponse) {

		try {
			AuthenticationRequestRepository authenticationRequestRepo = this.getTenantRepoFactory().getAuthenticationRequestRepo();
			AuthenticationRequest request = authenticationRequestRepo.get(authenticationRequestHref);
			if (request == null) {
				String error = "Unable to find the authentication request with HREF: " + authenticationRequestHref;
				logger.error(error);
				throw new RuntimeException(error);
			}
			request.setFidoAuthenticationResponse(authResponse);
			request = authenticationRequestRepo.update(request);
			
			// User was authenticated
			if (request.getStatus() == AuthenticationRequestStatusEnum.COMPLETED_SUCCESSFUL) {
				UserRepository userRepo = this.getTenantRepoFactory().getUserRepo();
				if (request.getUser() != null) {
					request.setUser(userRepo.get(request.getUser().getHref()));
				}
				return request;
			}
			
			// User was not authenticated
			if (request.getStatus() == AuthenticationRequestStatusEnum.COMPLETED_FAILURE) {
				com.daon.identityx.controller.model.Error error = null;
				
				if (request.getFidoResponseCode() != null) {
					int code = (int)(long)request.getFidoResponseCode();
					switch (code) {
						case 1481:
							error = com.daon.identityx.controller.model.Error.UNKNOWN_AUTHENTICATOR;
							error.setFidoResponseCode(1481L);
							error.setFidoResponseMsg("This authenticator is not known - please delete it");
							break;
						case 1493:
							//Maybe the FIDO client can do something about this so the details will be returned
							error = com.daon.identityx.controller.model.Error.REVOKED_AUTHENTICATOR;
							error.setFidoResponseCode(1493L);
							error.setFidoResponseMsg("This authenticator is no longer valid - please delete it");
							break;
						default:
							error = com.daon.identityx.controller.model.Error.INVALID_CREDENTIALS;
					}
				}
				throw new ProcessingException(error);
			}
			
			String error = "Response could not be validated";
			logger.error(error);
			throw new RuntimeException(error);

		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to update the registration challenge.  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}

	/***
	 * Get the FIDO Facets for the application which can be returned to the FIDO Client
	 * 
	 * @return
	 */
	@Override
	public FIDOFacets getFidoFacets() {
		Application app;
		try {
			app = this.findApplication();
		} catch (IdxRestException e) {
			String error = "Application could not be found";
			logger.error(error);
			throw new RuntimeException(error);
		}
		return app.getFidoFacets();
	}

	
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
	@Override
	public AuthenticatorInfo getAuthenticator(String idxId, String id) {
	
		try {
			AuthenticatorRepository authRepo = this.getTenantRepoFactory().getAuthenticatorRepo();
			Authenticator authenticator = authRepo.getById(id);
			
			String userId = this.getIdFromHref(authenticator.getUser().getHref());
			if (!idxId.equals(userId)) {
				String error = "The authenticator requested does not belong to the IdentityX user with ID: " + idxId;
				logger.error(error);
				throw new RuntimeException(error);
			}
			AuthenticatorInfo authInfo = this.convert(authenticator);
			return authInfo;
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to retrieve the authenticator.  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}


	@Override
	public PolicyInfo getRegistrationPolicyInfo() {
		try {
			return this.convert(getPolicy(getRegPolicyHref()));
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to retrieve the registration policy.  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}

	@Override
	public PolicyInfo getAuthenticationPolicyInfo() {
		try {
			return this.convert(getPolicy(getAuthPolicyHref()));
		} catch (IdxRestException ex) {
			String error = "An exception occurred while attempting to retrieve the authentication policy.  Exception: " + ex.getMessage();
			logger.error(error, ex);
			throw new RuntimeException(error, ex);
		}
	}


	/***
	 * Find the application within IdentityX where the is retrieved from the "applicationId" property.
	 * Uses an ApplicationRepositity and performs a "list" operation.
	 *  
	 * @return
	 * @throws IdxRestException
	 */
	protected Application findApplication() throws IdxRestException {

		ApplicationRepository applicationRepo = tenantRepoFactory.getApplicationRepo();
		ApplicationQueryHolder holder = new ApplicationQueryHolder();
		holder.getSearchSpec().setApplicationId(this.getApplicationId());
		ApplicationCollection applicationCollection = applicationRepo.list(holder);

		switch (applicationCollection.getItems().length) {
		case 0:
			throw new RuntimeException("Could not find an application with the ApplicationId: " + this.getApplicationId());
		case 1:
			return applicationCollection.getItems()[0];
		default:
			throw new RuntimeException("More than one application with the same ApplicationId!!!!");
		}
	}

	/***
	 * Uses the specified policyHref to get the policy as not all content will 
	 * be provided in the list operation. For instance, the fido policy itself will 
	 * not be present unless the policy is retrieved in a GET operation.
	 * 
	 * @param policyHref
	 * @return
	 * @throws IdxRestException
	 */
	protected Policy getPolicy(String policyHref) throws IdxRestException {
		PolicyRepository policyRepo = this.getTenantRepoFactory().getPolicyRepo();
		return policyRepo.get(policyHref);
	}

	/***
	 * Find the policy within IdentityX with the name supplied and which is part of the "application".
	 * Uses an PolicyRepository and performs a "list" operation.
	 * 
	 * @param aPolicyId
	 * @return
	 * @throws IdxRestException
	 */
	protected Policy findPolicy(String aPolicyId) throws IdxRestException {

		PolicyQueryHolder holder = new PolicyQueryHolder();
		holder.getSearchSpec().setPolicyId(aPolicyId);
		PolicyRepository policyRepo = this.getTenantRepoFactory().getPolicyRepo();
		PolicyCollection policyCollection = policyRepo.list(this.getApplication().getPolicies().getHref(), holder);
		switch (policyCollection.getItems().length) {
		case 0:
			throw new RuntimeException("Could not find a policy with the PolicyId: " + aPolicyId);
		case 1:
			return policyCollection.getItems()[0];
		default:
			throw new RuntimeException("There is more than one policy with the name: " + aPolicyId);
		}
	}

	/***
	 * Adds a new registration challenge to the registration.
	 * 
	 * @param reg
	 * @return
	 * @throws IdxRestException
	 */
	protected RegistrationChallenge addRegistrationChallenge(Registration reg) throws IdxRestException {

		RegistrationChallengeRepository regChallengeRepository = this.getTenantRepoFactory().getRegistrationChallengeRepo();
		RegistrationChallenge regChallenge = new RegistrationChallenge();
		regChallenge.setRegistration(reg);
		regChallenge.setPolicy(new Policy(this.getRegPolicyHref()));
		regChallenge = regChallengeRepository.create(regChallenge);
		logger.debug("Added a registration challenge for Registration with registrationId: {}, - regChallengeId: {}", reg.getRegistrationId(), regChallenge.getId());
		return regChallenge;
	}

	/***
	 * Adds a new registration to the user and application with the provided registraionId.
	 *  
	 * @param user
	 * @param registrationId
	 * @return
	 * @throws IdxRestException
	 */
	protected Registration addRegistration(User user, String registrationId) throws IdxRestException {

		RegistrationRepository regRepo = this.getTenantRepoFactory().getRegistrationRepo();
		Registration reg = new Registration();
		reg.setUser(user);
		reg.setApplication(this.getApplication());
		reg.setRegistrationId(registrationId);
		reg = regRepo.create(reg);
		logger.debug("Added a registration for User with userId: {}, - registrationId: {}", user.getUserId(), reg.getId());
		return reg;
	}

	/***
	 * Archived (deactivates) the registration for the user with the provided registrationId.
	 * 
	 * @param user
	 * @param registrationId
	 * @throws IdxRestException
	 */
	protected void achiveRegistration(User user, String registrationId) throws IdxRestException {

		Registration registration = this.findRegistration(user, registrationId);
		if (registration == null) {
			logger.debug("Nothing to do - the registration does not exist or is already archived");
		} else {
			RegistrationRepository regRepo = this.getTenantRepoFactory().getRegistrationRepo();
			regRepo.archive(registration);
		}
	}

	/***
	 * Convert the id to a registration HREF and retrieve the associated registration from IdentityX
	 * 
	 * @param id
	 * @return
	 * @throws IdxRestException
	 */
	protected Registration getRegistrationFromId(String id) throws IdxRestException {
		
		RegistrationRepository regRepo = this.getTenantRepoFactory().getRegistrationRepo();
		return regRepo.getById(id);
	}
	
	/***
	 * Retrieve the registration with the provided HREF from IdentityX
	 * @param href
	 * @return
	 * @throws IdxRestException
	 */
	protected Registration getRegistrationFromHref(String href) throws IdxRestException {
		
		RegistrationRepository regRepo = this.getTenantRepoFactory().getRegistrationRepo();
		return regRepo.get(href);
	}
	
	/***
	 * Find the registration within IdentityX with the name supplied associated with the user.
	 * Uses an RegistrationRepository and performs a "list" operation.

	 * @param user
	 * @param registrationId
	 * @return
	 * @throws IdxRestException
	 */
	protected Registration findRegistration(User user, String registrationId) throws IdxRestException {

		RegistrationRepository regRepo = this.getTenantRepoFactory().getRegistrationRepo();
		RegistrationQueryHolder holder = new RegistrationQueryHolder();
		holder.getSearchSpec().setRegistrationId(registrationId);
		RegistrationCollection registrationCollection = regRepo.list(user.getRegistrations().getHref(), holder);
		if (registrationCollection.getItems() == null) {
			return null;
		}
		switch (registrationCollection.getItems().length) {
		case 0:
			return null;
		case 1:
			return registrationCollection.getItems()[0];
		default:
			throw new RuntimeException("More than one registration with the same RegistrationId!!!!");
		}
	}

	/***
	 * Retrieves a list of authenticators from IdentityX.
	 * 
	 * @param authenticatorsHref
	 * @return
	 * @throws IdxRestException
	 */
	protected Authenticator[] getAuthenticators(String authenticatorsHref) throws IdxRestException {
		AuthenticatorRepository authRepo = this.getTenantRepoFactory().getAuthenticatorRepo();
		AuthenticatorQueryHolder holder = new AuthenticatorQueryHolder();
		AuthenticatorCollection authenticatorCollection = authRepo.list(authenticatorsHref, holder);

		// Expand tenant authenticator type info
		for (Authenticator authenticator : authenticatorCollection.getItems()) {
			
			authenticator.setAuthenticatorType(this.getAuthenticatorType(authenticator.getAuthenticatorType().getHref()));
		}

		return authenticatorCollection.getItems();
	}

	/***
	 * Add a user to IdentityX
	 * 
	 * @param userId
	 * @return
	 * @throws IdxRestException
	 */
	protected User addUser(String userId) throws IdxRestException {

		UserRepository userRepo = this.getTenantRepoFactory().getUserRepo();
		User aUser = new User();
		aUser.setUserId(userId);
		aUser = userRepo.create(aUser);
		logger.debug("Added user to IdentityX with userId: {}, - generated ID: {}", userId, aUser.getId());
		return aUser;
	}
	
	/***
	 * Converts an Id to a user HREF
	 * 
	 * @param id
	 * @return
	 */
	protected String getHrefFromUserId(String id) {
		UserRepository userRepo = this.getTenantRepoFactory().getUserRepo();
		return userRepo.getBaseUrl() + userRepo.getResourcePath() + "/" + id;
	}

	/***
	 * Converts an HREF to an Id 
	 * 
	 * @param id
	 * @return
	 */
	protected String getIdFromHref(String href) {
		
		int lastIndex = href.lastIndexOf("/");
		if (lastIndex < 0 || lastIndex > href.length()) {
			return "";
		} else {
			return href.substring(lastIndex+1);
		}
	}

	/***
	 * Gets the user from IdentityX with the specified ID
	 * 
	 * @param id
	 * @return
	 * @throws IdxRestException
	 */
	protected User getUser(String id) throws IdxRestException {
		
		UserRepository userRepo = this.getTenantRepoFactory().getUserRepo();
		return userRepo.getById(id);
	}
	
	/***
	 * Find the user in IdentityX with the specified userId.
	 * 
	 * @param userId
	 * @return
	 * @throws IdxRestException
	 */
	protected User findUser(String userId) throws IdxRestException {

		UserRepository userRepo = this.getTenantRepoFactory().getUserRepo();
		UserQueryHolder holder = new UserQueryHolder();
		holder.getSearchSpec().setUserId(userId);
		UserCollection userCollection = userRepo.list(holder);
		if (userCollection.getItems() == null) {
			return null;
		}
		switch (userCollection.getItems().length) {
		case 0:
			return null;
		case 1:
			return userCollection.getItems()[0];
		default:
			throw new RuntimeException("More than one user with the same UserId!!!!");
		}
	}

	/***
	 * Finds all the FIDO authenticators within IdentityX and converts them to AuthenticatorInfo objects
	 * to be returned to the app.
	 *  
	 * @param authenticators
	 * @return
	 */
	protected AuthenticatorInfo[] convertToAuthenticatorInfo(Authenticator[] authenticators) {

		List<AuthenticatorInfo> authenticatorInfoList = new ArrayList<>();

		for (Authenticator authenticator : authenticators) {
			// Create a list of relevant information about FIDO authenticators whose AAIDs match those
			// available on the client device
			if (authenticator.getType().equals(FIDO_AUTHENTICATOR_TYPE)) {
				AuthenticatorInfo authenticatorInfo = this.convert(authenticator);
				authenticatorInfoList.add(authenticatorInfo);
			}
		}

		return authenticatorInfoList.toArray(new AuthenticatorInfo[0]);
	}
	
	/***
	 * Convert the details from the authenticator to the AuthenticatorInfo, an abbreviated
	 * object which is sent to the app
	 * 
	 * @param authenticator
	 * @return
	 */
	protected AuthenticatorInfo convert(Authenticator authenticator) {
		
		AuthenticatorInfo authenticatorInfo = new AuthenticatorInfo();
		authenticatorInfo.setId(authenticator.getId());
		authenticatorInfo.setCreated(authenticator.getCreated());
		authenticatorInfo.setLastUsed(authenticator.getUpdated());
		authenticatorInfo.setName(authenticator.getAuthenticatorType().getName());
		authenticatorInfo.setDescription(authenticator.getAuthenticatorType().getDescription());
		authenticatorInfo.setVendorName(authenticator.getAuthenticatorType().getVendorName());
		authenticatorInfo.setIcon(authenticator.getAuthenticatorType().getIcon());
		authenticatorInfo.setFidoDeregistrationRequest(authenticator.getFidoDeregistrationRequest());
		authenticatorInfo.setStatus(authenticator.getStatus().name());
		authenticatorInfo.setAaid(authenticator.getAuthenticatorType().getAaid());
		return authenticatorInfo;
	}

	protected PolicyInfo convert(Policy policy) {

		PolicyInfo policyInfo = new PolicyInfo();
		policyInfo.setId(policy.getId());
		policyInfo.setType(policy.getType().toString());
		if (policy.getFidoPolicy() != null) {
			try {
				policyInfo.setPolicy(objectMapper.writeValueAsString(policy.getFidoPolicy()));
			} catch (JsonProcessingException e) {
				String error = "An exception occurred while attempting to convert a FIDO policy object to a string";
				logger.error(error, e);
				throw new RuntimeException(error, e); 
			}
		}
		return policyInfo;
	}

	public String getApplicationId() {
		return applicationId;
	}

	public void setApplicationId(String applicationId) {
		this.applicationId = applicationId;
	}

	public String getRegPolicyId() {
		return regPolicyId;
	}

	public void setRegPolicyId(String regPolicyId) {
		this.regPolicyId = regPolicyId;
	}

	public String getAuthPolicyId() {
		return authPolicyId;
	}

	public void setAuthPolicyId(String authPolicyId) {
		this.authPolicyId = authPolicyId;
	}

	public TenantRepoFactory getTenantRepoFactory() {
		return tenantRepoFactory;
	}

	public void setTenantRepoFactory(TenantRepoFactory tenantRepoFactory) {
		this.tenantRepoFactory = tenantRepoFactory;
	}

	public void setApplication(Application application) {
		this.application = application;
	}

	public String getRegPolicyHref() {
		return regPolicyHref;
	}

	public void setRegPolicyHref(String regPolicyHref) {
		this.regPolicyHref = regPolicyHref;
	}

	public String getAuthPolicyHref() {
		return authPolicyHref;
	}

	public void setAuthPolicyHref(String authPolicyHref) {
		this.authPolicyHref = authPolicyHref;
	}

	public Application getApplication() {
		return application;
	}

	public String getKeystoreLocation() {
		return keystoreLocation;
	}

	public void setKeystoreLocation(String keystoreLocation) {
		this.keystoreLocation = keystoreLocation;
	}

	public String getKeystorePassword() {
		return keystorePassword;
	}

	public void setKeystorePassword(String keystorePassword) {
		this.keystorePassword = keystorePassword;
	}

	public String getKeystoreKeyAlias() {
		return keystoreKeyAlias;
	}

	public void setKeystoreKeyAlias(String keystoreKeyAlias) {
		this.keystoreKeyAlias = keystoreKeyAlias;
	}

	public String getKeystoreKeyPassword() {
		return keystoreKeyPassword;
	}

	public void setKeystoreKeyPassword(String keystoreKeyPassword) {
		this.keystoreKeyPassword = keystoreKeyPassword;
	}

	public String getCredentialPropertiesLocation() {
		return credentialPropertiesLocation;
	}

	public void setCredentialPropertiesLocation(String credentialPropertiesLocation) {
		this.credentialPropertiesLocation = credentialPropertiesLocation;
	}

	public Map<String, AuthenticatorType> getAuthenticatorTypesCache() {
		return authenticatorTypesCache;
	}

}
