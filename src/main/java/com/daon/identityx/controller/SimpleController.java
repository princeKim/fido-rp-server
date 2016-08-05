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

package com.daon.identityx.controller;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Arrays;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.client.HttpClientErrorException;

import com.daon.identityx.controller.model.AuthenticationMethod;
import com.daon.identityx.controller.model.AuthenticatorInfo;
import com.daon.identityx.controller.model.CreateAccount;
import com.daon.identityx.controller.model.CreateAccountResponse;
import com.daon.identityx.controller.model.CreateAuthRequestResponse;
import com.daon.identityx.controller.model.CreateAuthenticator;
import com.daon.identityx.controller.model.CreateAuthenticatorResponse;
import com.daon.identityx.controller.model.CreateRegRequestResponse;
import com.daon.identityx.controller.model.CreateSession;
import com.daon.identityx.controller.model.CreateSessionResponse;
import com.daon.identityx.controller.model.CreateTransactionAuthRequest;
import com.daon.identityx.controller.model.DeleteAccountResponse;
import com.daon.identityx.controller.model.Error;
import com.daon.identityx.controller.model.GetAuthenticatorResponse;
import com.daon.identityx.controller.model.GetPolicyResponse;
import com.daon.identityx.controller.model.ListAuthenticatorsResponse;
import com.daon.identityx.controller.model.ValidateTransactionAuth;
import com.daon.identityx.controller.model.ValidateTransactionAuthResponse;
import com.daon.identityx.entity.Account;
import com.daon.identityx.entity.Audit;
import com.daon.identityx.entity.AuditAction;
import com.daon.identityx.entity.Session;
import com.daon.identityx.exception.ProcessingException;
import com.daon.identityx.fido.FIDORegChallengeAndId;
import com.daon.identityx.fido.IIdentityXServices;
import com.daon.identityx.repository.AccountRepository;
import com.daon.identityx.repository.AuditRepository;
import com.daon.identityx.repository.SessionRepository;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.daon.identityx.rest.model.pojo.FIDOFacets;
import com.daon.identityx.rest.model.pojo.RegistrationChallenge;

/***
 * This class presents the REST interface to the sample application.
 * 
 * @author Daon
 *
 */
@Controller
@RequestMapping("/")
public class SimpleController {

	private static final Logger logger = LoggerFactory.getLogger(SimpleController.class);

	private final static int BASE_ITERATION_NUMBER = 10000;

	@Autowired
	private AccountRepository accountRepository;
	@Autowired
	private AuditRepository auditRepository;
	@Autowired
	private SessionRepository sessionRepository;
	@Autowired
	private IIdentityXServices identityXServices;

	@Value("${fido.session_period:900000}")
	private long sessionPeriod;

	private SecureRandom random;

	/***
	 * If an exception of type ProcessingException is caught, get the Error from it and return that to the caller 
	 * with a HTTP response code of BAD_REQUEST
	 * 
	 * @param ex
	 * @return
	 */
	@ExceptionHandler(ProcessingException.class)
	@ResponseStatus(value = HttpStatus.BAD_REQUEST)
	@ResponseBody
	public Error handleExpectedException(ProcessingException ex) {

		logger.error("An exception occurred while attempting to process the request.  Exception: " + ex.getError());
		return ex.getError();
	}

	/**
	 * The a web method throws an exception with a http status, then we controller will pass this detail
	 * back to the client.
	 * 
	 * @param ex
	 * @return
	 */
	@ExceptionHandler(HttpClientErrorException.class)
	@ResponseBody
	public Error handleHttpExceptions(HttpClientErrorException ex, HttpServletResponse response) {
		logger.error("An unexpected exception occurred while attempting to process the request. Exception: " + ex.getMessage());
		response.setStatus(ex.getStatusCode().value());
		return new Error(ex.getStatusCode().value(), ex.getStatusText());
	}

	/***
	 * If any other exception (other than ProcessingException) is caught, return an UNEXPECTED_ERROR  to the caller
	 * 
	 * @param ex
	 * @return
	 */
	@ExceptionHandler(Throwable.class)
	@ResponseStatus(value = HttpStatus.BAD_REQUEST)
	@ResponseBody
	public Error handleUnexpectedException(Throwable ex) {

		logger.error("An unexpected exception occurred while attempting to process the request.  Exception: " + ex.getMessage());
		return Error.UNEXPECTED_ERROR;
	}

	/***
	 * UNPROTECTED OPERATION - No session is required to perform this operation
	 * If this server is running with TLS then the facets can be retrieved through this operation
	 * @return
	 */
	@RequestMapping(value = "facets", method = RequestMethod.GET)
	@ResponseStatus(value = HttpStatus.OK)
	public @ResponseBody FIDOFacets getFidoFacets() {
		logger.info("***** Received a request for facets");
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.GET_FACETS);
		try {
			return this.getIdentityXServices().getFidoFacets();
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request for facets - duration: {}ms", (System.currentTimeMillis() - start));
		}
	}


	/***
	 * UNPROTECTED OPERATION - No session is required to perform this operation
	 * This operation creates an account for the user based on the details passed
	 * @param createAccount
	 * @return
	 */
	@RequestMapping(value = "accounts", method = RequestMethod.POST, consumes = { "application/json" })
	@ResponseStatus(value = HttpStatus.CREATED)
	public @ResponseBody CreateAccountResponse createAccount(@RequestBody CreateAccount createAccount) {

		logger.info("***** Received a request to create an account");
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.CREATE_ACCOUNT);

		if (createAccount.getEmail() == null || createAccount.getEmail().length() == 0) {
			throw new ProcessingException(Error.EMAIL_NOT_PROVIDED);
		}
		if (createAccount.getPassword() == null || createAccount.getPassword().length() == 0) {
			throw new ProcessingException(Error.PASSWORD_NOT_PROVIDED);
		}
		if (createAccount.getFirstName() == null || createAccount.getFirstName().length() == 0) {
			throw new ProcessingException(Error.FIRST_NAME_NOT_PROVIDED);
		}
		if (createAccount.getLastName() == null || createAccount.getLastName().length() == 0) {
			throw new ProcessingException(Error.LAST_NAME_NOT_PROVIDED);
		}

		Account newAccount = new Account(createAccount);

		this.createHash(newAccount, createAccount.getPassword());
		Timestamp now = new Timestamp(System.currentTimeMillis());
		newAccount.setCreatedDTM(now);
		newAccount.setLastLoggedIn(now);

		try {

			newAccount = this.getAccountRepository().save(newAccount);
			Session aSession = new Session(newAccount, sessionPeriod);
			aSession = this.getSessionRepository().save(aSession);

			CreateAccountResponse createAccountResponse = new CreateAccountResponse();
			createAccountResponse.setSessionId(aSession.getId());
			if (createAccount.isRegistrationRequested()) {
				FIDORegChallengeAndId regChallengeAndId = this.getIdentityXServices().createRegRequest(createAccount.getEmail(), null);
				newAccount.setIdXId(regChallengeAndId.getIdXId());
				this.getAccountRepository().save(newAccount);
				createAccountResponse.setFidoRegistrationRequest(regChallengeAndId.getRegistrationChallenge().getFidoRegistrationRequest());
				createAccountResponse.setRegistrationRequestId(regChallengeAndId.getRegistrationChallenge().getHref());
			}
			return createAccountResponse;
		} catch (DataIntegrityViolationException ex) {
			throw new ProcessingException(Error.ACCOUNT_ALREADY_EXISTS);
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to createAccount - duration: {}ms", (System.currentTimeMillis() - start));
		}

	}

	/***
	 * UNPROTECTED OPERATION - No session is required to perform this operation
	 * This operations creates a FIDO authentication request to allow the user to perform a FIDO authentication
	 * and thus create a session. 
	 * @param createAuth
	 * @return
	 */
	@RequestMapping(value = "authRequests", method = RequestMethod.GET, consumes = { "application/json" })
	@ResponseStatus(value = HttpStatus.CREATED)
	public @ResponseBody CreateAuthRequestResponse createAuthRequest() {

		logger.info("***** Received a request to create an authentication request");
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.CREATE_AUTH_REQUEST);
		try {
			AuthenticationRequest request = this.getIdentityXServices().createAuthRequest();
			CreateAuthRequestResponse response = new CreateAuthRequestResponse();
			response.setAuthenticationRequestId(request.getHref());
			response.setFidoAuthenticationRequest(request.getFidoAuthenticationRequest());
			return response;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to createAuthenticationRequest - duration: {}ms", (System.currentTimeMillis() - start));
		}
	}

	/***
	 * UNPROTECTED OPERATION - No session is required to perform this operation
	 * This operation creates a session for the user based on the credentials provided (FIDO or Username/Password)
	 * @param createSession
	 * @return
	 */
	@RequestMapping(value = "sessions", method = RequestMethod.POST, consumes = { "application/json" })
	@ResponseStatus(value = HttpStatus.CREATED)
	public @ResponseBody CreateSessionResponse createSession(@RequestBody CreateSession createSession) {

		logger.info("***** Receive response to create a session");
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.CREATE_SESSION);
		try {
			if (createSession.getEmail() != null && createSession.getEmail().length() > 0) {
				return this.createSessionWithEmail(createSession);
			}
			if (createSession.getFidoAuthenticationResponse() != null && createSession.getFidoAuthenticationResponse().length() > 0) {
				return this.createSessionWithFIDO(createSession);
			}
			String error = "To authenticate, please supply either an email and password or a FIDO authentication response";
			logger.error(error);
			throw new ProcessingException(Error.INSUFFICIENT_CREDENTIALS);

		} catch (Exception e) {
			throw e;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to createSession - duration: {}ms", (System.currentTimeMillis() - start));
		}

	}

	/***
	 * PROTECTED OPERATION - The caller must have a valid session to perform this operation
	 * This operation will delete the account associated with the session
	 * @param sessionId
	 */
	@RequestMapping(value = "accounts/{id}", method = RequestMethod.DELETE)
	@ResponseStatus(value = HttpStatus.OK)
	public @ResponseBody DeleteAccountResponse deleteAccountBySessionId(@PathVariable("id") String sessionId) {

		logger.info("***** Received a request to delete account: {}", sessionId);
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.DELETE_ACCOUNT);
		try {
			Session session = this.validateSession(sessionId);
			Account account = this.getAccountRepository().findById(session.getAccountId());
			DeleteAccountResponse response = new DeleteAccountResponse();
			if (account.getIdXId() != null) {
				AuthenticatorInfo[] fidoDeregReqs = this.getIdentityXServices().deactivateAndDelete(account.getIdXId());
				response.setFidoDeregistrationRequests(fidoDeregReqs);
			}
			anAudit.setAccountId(account.getId());
			this.getAccountRepository().delete(account.getId());
			this.getSessionRepository().delete(session);
			return response;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to deleteAccount - duration: {}ms", (System.currentTimeMillis() - start));
		}
	}

	/***
	 * PROTECTED OPERATION - The caller must have a valid session to perform this operation
	 * This operation will validate the transaction from the FIDO authenticator - demonstrating secure transaction confirmation 
	 * @param email
	 */
	@RequestMapping(value = "transactionAuthValidation", method = RequestMethod.POST, consumes = { "application/json" })
	@ResponseStatus(value = HttpStatus.CREATED)
	public @ResponseBody ValidateTransactionAuthResponse validateTransactionAuth(@RequestHeader("Session-Id") String sessionId, 
			@RequestBody ValidateTransactionAuth validateTransactionAuth) {

		logger.info("***** Received a request to validate an authentication tranaction for session: {}", sessionId);
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.VALIDATE_TRANSACTION_AUTH);
		try {
			Session session = this.validateSession(sessionId);
			Account account = this.getAccountRepository().findById(session.getAccountId());
			anAudit.setAccountId(account.getId());

			if (validateTransactionAuth.getAuthenticationRequestId() == null
					|| validateTransactionAuth.getAuthenticationRequestId().length() == 0) {
				throw new ProcessingException(Error.AUTHENTICATION_REQUEST_ID_NOT_PROVIDED);
			}

			AuthenticationRequest authRequest = this.getIdentityXServices().validateAuthResponse( 
					validateTransactionAuth.getAuthenticationRequestId(), validateTransactionAuth.getFidoAuthenticationResponse());

			ValidateTransactionAuthResponse response = new ValidateTransactionAuthResponse();
			response.setFidoAuthenticationResponse(authRequest.getFidoAuthenticationResponse());
			response.setFidoResponseCode(authRequest.getFidoResponseCode());
			response.setFidoResponseMsg(authRequest.getFidoResponseMsg());

			return response;
		} catch (Exception e) {
			throw e;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to validateTransactionAuth - duration: {}ms", (System.currentTimeMillis() - start));
		}

	}

	/***
	 * PROTECTED OPERATION - The caller must have a valid session to perform this operation
	 * This is the "logout" operation - called when the user opts to logout
	 * @param id
	 */
	@RequestMapping(value = "sessions/{sessionId}", method = RequestMethod.DELETE)
	@ResponseStatus(value = HttpStatus.OK)
	public @ResponseBody void deleteSession(@PathVariable String sessionId) {

		logger.info("***** Received a request to delete session: {}", sessionId);
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.DELETE_SESSION);
		try {
			Session session = this.validateSession(sessionId);
			this.getSessionRepository().delete(session);

		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to deleteSession - duration: {}ms", (System.currentTimeMillis() - start));
		}
	}

	/***
	 * PROTECTED OPERATION - The caller must have a valid session to perform this operation
	 * This operation creates a transaction authentication request for the user.
	 * @param createTransaction
	 * @return
	 */
	@RequestMapping(value = "transactionAuthRequests", method = RequestMethod.POST, consumes = { "application/json" })
	@ResponseStatus(value = HttpStatus.CREATED)
	public @ResponseBody CreateAuthRequestResponse createTransactionAuthRequest(@RequestHeader("Session-Id") String sessionId, @RequestBody CreateTransactionAuthRequest createTransaction) {

		logger.info("***** Received a request to create a transaction authentication request for session: {}", sessionId);
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.CREATE_TRANSACTION_AUTH_REQUEST);
		try {
			Session session = this.validateSession(sessionId);
			Account account = this.getAccountRepository().findById(session.getAccountId());
			anAudit.setAccountId(account.getId());

			AuthenticationRequest request = this.getIdentityXServices().createAuthTransactionRequest(account.getIdXId(),
					createTransaction.getTransactionContentType(), createTransaction.getTransactionContent(),
					createTransaction.isStepUpAuth());
			CreateAuthRequestResponse response = new CreateAuthRequestResponse();
			response.setAuthenticationRequestId(request.getHref());
			response.setFidoAuthenticationRequest(request.getFidoAuthenticationRequest());
			return response;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to createTransactionAuthRequest - duration: {}ms", (System.currentTimeMillis() - start));
		}
	}

	/***
	 * PROTECTED OPERATION - The caller must have a valid session to perform this operation
	 * This sends a request to the FIDO server to create a registration request. The "user" is determined from the account associated with
	 * the session. A user will be created in FIDO with the email address associated with the account as the userId.
	 * 
	 * @param createReg
	 * @return
	 */
	@RequestMapping(value = "regRequests", method = RequestMethod.GET, consumes = { "application/json" })
	@ResponseStatus(value = HttpStatus.CREATED)
	public @ResponseBody CreateRegRequestResponse createRegRequest(@RequestHeader("Session-Id") String sessionId) {

		logger.info("***** Received a request to create a registration request for session: {}", sessionId);
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.CREATE_REG_REQUEST);
		try {
			Session session = this.validateSession(sessionId);
			Account account = this.getAccountRepository().findById(session.getAccountId());
			anAudit.setAccountId(account.getId());
			FIDORegChallengeAndId regChallengeAndId = this.getIdentityXServices().createRegRequest(account.getEmail(), account.getIdXId());
			if (account.getIdXId() == null) {
				account.setIdXId(regChallengeAndId.getIdXId());
				this.getAccountRepository().save(account);
			} else {
				if (!account.getIdXId().equals(regChallengeAndId.getIdXId())) {
					String error = "The FIDO Id from the account and the FIDO ID from the FIDO server are different! - this is an error!";
					logger.error(error);
					throw new RuntimeException(error);
				}
			}
			CreateRegRequestResponse response = new CreateRegRequestResponse();
			response.setRegistrationRequestId(regChallengeAndId.getRegistrationChallenge().getHref());
			response.setFidoRegistrationRequest(regChallengeAndId.getRegistrationChallenge().getFidoRegistrationRequest());
			return response;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to createRegRequest - duration: {}ms", (System.currentTimeMillis() - start));
		}

	}

	/***
	 * PROTECTED OPERATION - The caller must have a valid session to perform this operation
	 * This request takes the response from the FIDO client to a registration request and sends it to the FIDO server. Assuming the FIDO
	 * server can process it correctly, a registration confirmation message is returned which is to be sent to the FIDO client to confirm a
	 * successful registration.
	 * 
	 * This operation will create an authenticator for the requested user.
	 * 
	 * @param createAuth
	 * @return
	 */
	@RequestMapping(value = "authenticators", method = RequestMethod.POST, consumes = { "application/json" })
	@ResponseStatus(value = HttpStatus.CREATED)
	public @ResponseBody CreateAuthenticatorResponse createAuthenticator(@RequestHeader("Session-Id") String sessionId, @RequestBody CreateAuthenticator createAuth) {

		logger.info("***** Received request to create an authenticator for session: {}", sessionId);
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.CREATE_AUTHENTICATOR);
		try {
			Session session = this.validateSession(sessionId);
			anAudit.setSessionId(sessionId);
			Account account = this.getAccountRepository().findById(session.getAccountId());
			RegistrationChallenge challenge = this.getIdentityXServices().processRegistrationResponse(account.getIdXId(), createAuth.getRegistrationChallengeId(),
					createAuth.getFidoReqistrationResponse());
			CreateAuthenticatorResponse response = new CreateAuthenticatorResponse();
			response.setFidoRegistrationConfirmation(challenge.getFidoRegistrationResponse());
			response.setFidoResponseCode(challenge.getFidoResponseCode());
			response.setFidoResponseMsg(challenge.getFidoResponseMsg());
			return response;

		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to createAuthenticator - duration: {}ms", (System.currentTimeMillis() - start));
		}
	}

	/**
	 * PROTECTED OPERATION - The caller must have a valid session to perform this operation
	 * Deregister an authenticator
	 * 
	 * @param href
	 *            Authenticator href
	 * @return FIDO Deregistration request JSON string
	 */
	@RequestMapping(value = "authenticators/{id}", method = RequestMethod.DELETE)
	@ResponseStatus(value = HttpStatus.OK)
	public @ResponseBody String deleteAuthenticator(@RequestHeader("Session-Id") String sessionId, @PathVariable String id) {

		logger.info("***** Received request to delete authenticator: {} for session: {} ", id, sessionId);
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.DELETE_AUTHENTICATOR);	
		try {
			Session session = this.validateSession(sessionId);
			// TODO - NEED TO CHECK THE REG CHALLENGE IS FOR THE SAME USER
			Account account = this.getAccountRepository().findById(session.getAccountId());
			return this.getIdentityXServices().deleteAuthenticator(account.getIdXId(), id);
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to deleteAuthenticator - duration: {}ms", (System.currentTimeMillis() - start));
		}
	}

	/***
	 * PROTECTED OPERATION - The caller must have a valid session to perform this operation
	 * Return a list of FIDO authenticators for the account associated with this session
	 * 
	 * @param sessionId
	 * @return
	 */
	@RequestMapping(value = "listAuthenticators", method = RequestMethod.GET, consumes = { "application/json" })
	@ResponseStatus(value = HttpStatus.OK)
	public @ResponseBody ListAuthenticatorsResponse listAuthenticators(@RequestHeader("Session-Id") String sessionId) {

		logger.info("***** Received request to list authenticators for the account associated with session: {} ", sessionId);
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.LIST_AUTHENTICATORS);
		try {
			Session session = this.validateSession(sessionId);
			Account account = this.getAccountRepository().findById(session.getAccountId());
			anAudit.setAccountId(account.getId());
			AuthenticatorInfo[] authenticatorInfos = this.getIdentityXServices().listAuthenticators(account.getIdXId());
			ListAuthenticatorsResponse response = new ListAuthenticatorsResponse();
			response.setAuthenticatorInfoList(authenticatorInfos);
			return response;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to listAuthenticators - duration: {}ms", (System.currentTimeMillis() - start));
		}
	}

	/***
	 * PROTECTED OPERATION - The caller must have a valid session to perform this operation
	 * Get the details of the authenticator associated with the ID.
	 * 
	 * @param sessionId
	 * @param id
	 * @return
	 */
	@RequestMapping(value = "authenticators/{id}", method = RequestMethod.GET, consumes = { "application/json" })
	@ResponseStatus(value = HttpStatus.OK)
	public @ResponseBody GetAuthenticatorResponse getAuthenticator(@RequestHeader("Session-Id") String sessionId, @PathVariable("id") String id) {

		logger.info("***** Received request to get the authenticator; {} for session: {} ", id, sessionId);
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.GET_AUTHENTICATOR);
		try {
			Session session = this.validateSession(sessionId);
			Account account = this.getAccountRepository().findById(session.getAccountId());
			anAudit.setAccountId(account.getId());
			AuthenticatorInfo authenticatorInfo = this.getIdentityXServices().getAuthenticator(account.getIdXId(), id);
			GetAuthenticatorResponse response = new GetAuthenticatorResponse();
			response.setAuthenticatorInfo(authenticatorInfo);
			return response;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to getAuthenticator - duration: {}ms", (System.currentTimeMillis() - start));
		}
	}

	@RequestMapping(value = "policies/{id}", method = RequestMethod.GET, consumes = { "application/json" })
	@ResponseStatus(HttpStatus.OK)
	public @ResponseBody GetPolicyResponse getPolicy(@RequestHeader("Session-Id") String sessionId, @PathVariable("id") String id) {

		logger.info("***** Received request to get the policy: {} for session: {} ", id, sessionId);
		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.GET_POLICY);
		try {
			Session session = this.validateSession(sessionId);
			Account account = this.getAccountRepository().findById(session.getAccountId());
			anAudit.setAccountId(account.getId());
			GetPolicyResponse res = new GetPolicyResponse();
			if (id.equalsIgnoreCase("reg")) {
				res.setPolicyInfo(getIdentityXServices().getRegistrationPolicyInfo());
			} else if (id.equalsIgnoreCase("auth")) {
				res.setPolicyInfo(getIdentityXServices().getAuthenticationPolicyInfo());
			} else {
				throw new HttpClientErrorException(HttpStatus.NOT_FOUND, "Policy " + id);
			}
			return res;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
			logger.info("***** Sending response to the request to getPolicy - duration: {}ms", (System.currentTimeMillis() - start));
		}
	}

	/***
	 * Validate the session to ensure there is a session with the provided ID and the session has not expired
	 * 
	 * @param sessionId
	 * @return
	 */
	protected Session validateSession(String sessionId) {

		logger.debug("Attempting to validate the session: {}", sessionId);
		Session session = this.getSessionRepository().findById(sessionId);
		if (session == null) {
			logger.error("No session found for ID: {}", sessionId );
			throw new ProcessingException(Error.UNKNOWN_SESSION_IDENTIFIER);
		}

		if (session.getExpiringDTM().before(new Timestamp(System.currentTimeMillis()))) {
			logger.error("Session found for ID: {} but it has expired!", sessionId );
			throw new ProcessingException(Error.EXPIRED_SESSION);
		}

		session.setExpiringDTM(new Timestamp(System.currentTimeMillis() + Session.DEFAULT_SESSION_PERIOD));
		this.getSessionRepository().save(session);
		logger.debug("Updated the session: {} and extended the timeout period.", sessionId);
		return session;
	}

	/***
	 * Create a session with the given username (email) and password credentials
	 * 
	 * @param createSession
	 * @return
	 */
	protected CreateSessionResponse createSessionWithEmail(CreateSession createSession) {

		logger.debug("Attempting to create a session with username and password");
		if (createSession.getPassword() == null || createSession.getPassword().length() == 0) {
			logger.error("Cannot create a session as the password has not been provided");
			throw new ProcessingException(Error.PASSWORD_NOT_PROVIDED);
		}

		Account account = this.getAccountRepository().findByEmail(createSession.getEmail());
		if (account == null) {
			logger.error("Cannot create a session as there is no account with the email address: {}", createSession.getEmail());
			throw new ProcessingException(Error.INVALID_CREDENTIALS);
		}

		if (!this.validatePassword(account, createSession.getPassword())) {
			logger.error("The passwords don't match for user: " + createSession.getEmail());
			throw new ProcessingException(Error.INVALID_CREDENTIALS);
		}

		CreateSessionResponse sessionResponse = this.createSession(account, AuthenticationMethod.USERNAME_PASSWORD);
		sessionResponse.setEmail(account.getEmail());
		sessionResponse.setFirstName(account.getFirstName());
		sessionResponse.setLastName(account.getLastName());
		sessionResponse.setLastLoggedIn(account.getLastLoggedIn());

		// Update last login time
		account.setLastLoggedIn(new Timestamp(System.currentTimeMillis()));
		this.getAccountRepository().save(account);

		logger.debug("Session created for account: {}, session ID created at: {}", account.getEmail(), sessionResponse.getSessionId());
		return sessionResponse;
	}
	
	/***
	 * Create a session with the provided FIDO credentials
	 * 
	 * @param createSession
	 * @return
	 */
	protected CreateSessionResponse createSessionWithFIDO(CreateSession createSession) {

		logger.debug("Attempting to create a session with FIDO authentication");
		if (createSession.getAuthenticationRequestId() == null || createSession.getAuthenticationRequestId().length() == 0) {
			logger.error("Cannot create a session as the authentcation request ID has not been provided");
			throw new ProcessingException(Error.AUTHENTICATION_REQUEST_ID_NOT_PROVIDED);
		}

		AuthenticationRequest authRequest = this.getIdentityXServices().validateAuthResponse(createSession.getAuthenticationRequestId(),
				createSession.getFidoAuthenticationResponse());
		CreateSessionResponse sessionResponse = null;
		if (authRequest.getUser() == null) {
			//TODO - CAN THIS EVER BE RUN?
			sessionResponse = new CreateSessionResponse();
			sessionResponse.setFidoAuthenticationResponse(authRequest.getFidoAuthenticationResponse());
			sessionResponse.setFidoResponseCode(authRequest.getFidoResponseCode());
			sessionResponse.setFidoResponseMsg(authRequest.getFidoResponseMsg());

		} else {
			Account account = this.getAccountRepository().findByEmail(authRequest.getUser().getUserId());
			if (account == null) {
				logger.error("Cannot create a session as there is no account with the email address: {}", authRequest.getUser().getUserId());
				throw new ProcessingException(Error.FIDO_AUTH_COMPLETE_ACCOUNT_NOT_FOUND);
			}

			sessionResponse = this.createSession(account, AuthenticationMethod.FIDO_AUTHENTICATION);
			sessionResponse.setEmail(account.getEmail());
			sessionResponse.setFirstName(account.getFirstName());
			sessionResponse.setLastName(account.getLastName());
			sessionResponse.setFidoAuthenticationResponse(authRequest.getFidoAuthenticationResponse());
			sessionResponse.setFidoResponseCode(authRequest.getFidoResponseCode());
			sessionResponse.setFidoResponseMsg(authRequest.getFidoResponseMsg());
			sessionResponse.setLastLoggedIn(account.getLastLoggedIn());

			// Update last login time
			account.setLastLoggedIn(new Timestamp(System.currentTimeMillis()));
			this.getAccountRepository().save(account);
		}

		logger.debug("Session created for account: {}, session ID created at: {}", sessionResponse.getEmail(), sessionResponse.getSessionId());
		return sessionResponse;
	}

	/***
	 * Create a session for the given account
	 * 
	 * @param account
	 * @param authMethod
	 * @return
	 */
	protected CreateSessionResponse createSession(Account account, AuthenticationMethod authMethod) {
		Session session = new Session(account, sessionPeriod);
		this.getSessionRepository().save(session);
		CreateSessionResponse response = new CreateSessionResponse();
		response.setSessionId(session.getId());
		response.setLoggedInWith(authMethod);
		return response;
	}

	/***
	 * Hash the password for the given account
	 * 
	 * @param account
	 * @param password
	 */
	protected void createHash(Account account, String password) {

		byte[] salt = this.getRandomSalt();
		byte[] hashedPassword = this.hash(password, BASE_ITERATION_NUMBER, salt);
		account.setHashedPassword(hashedPassword);
		account.setIterations(BASE_ITERATION_NUMBER);
		account.setSalt(salt);
	}


	/***
	 * Validate the password provided against that of the account
	 * 
	 * @param account
	 * @param password
	 * @return
	 */
	protected boolean validatePassword(Account account, String password) {

		byte[] salt = account.getSalt();
		int iterationCount = account.getIterations();
		byte[] hashedPassword = this.hash(password, iterationCount, salt);
		return Arrays.equals(account.getHashedPassword(), hashedPassword);
	}


	/***
	 * Hash the password with the salt and for the given number of iterations
	 * 
	 * @param password
	 * @param iterationCount
	 * @param salt
	 * @return
	 */
	protected byte[] hash(String password, int iterationCount, byte[] salt) {

		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.reset();
			digest.update(salt);
			byte[] input = digest.digest(password.getBytes("UTF-8"));
			for (int i = 0; i < iterationCount; i++) {
				digest.reset();
				input = digest.digest(input);
			}
			return input;
		} catch (Exception e) {
			logger.error("An exception occurred while attempting to hash the password", e);
			throw new RuntimeException(e);
		}
	}

	/***
	 * Generate a random salt value for each account
	 * It would be better to use the strong instance of SecureRandom
	 * but on many Linux systems, it may take time for the /dev/random
	 * to contain the necessary number of bits required.  As this is a 
	 * demonstration, the algorithm has been changed to SHA1PRNG which
	 * is fast but not as secure.
	 * 
	 * @return
	 */
	protected synchronized byte[] getRandomSalt() {

		try {
			byte[] data = new byte[32];
			if (random == null) {
				random = SecureRandom.getInstance("SHA1PRNG");
				//random = SecureRandom.getInstanceStrong();  <- More secure
			}
			random.nextBytes(data);
			return data;
		} catch (Exception e) {
			logger.error("An excpetion occurred while attempting to generate the random salt", e);
			throw new RuntimeException(e);
		}

	}

	public AccountRepository getAccountRepository() {
		return accountRepository;
	}

	public void setAccountRepository(AccountRepository accountRepository) {
		this.accountRepository = accountRepository;
	}

	public AuditRepository getAuditRepository() {
		return auditRepository;
	}

	public void setAuditRepository(AuditRepository auditRepository) {
		this.auditRepository = auditRepository;
	}

	public SessionRepository getSessionRepository() {
		return sessionRepository;
	}

	public void setSessionRepository(SessionRepository sessionRepository) {
		this.sessionRepository = sessionRepository;
	}

	public IIdentityXServices getIdentityXServices() {
		return identityXServices;
	}

	public void setIdentityXServices(IIdentityXServices identityXServices) {
		this.identityXServices = identityXServices;
	}

}