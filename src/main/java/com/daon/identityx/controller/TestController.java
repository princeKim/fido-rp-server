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

import java.sql.Timestamp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import com.daon.identityx.controller.model.Error;
import com.daon.identityx.entity.Account;
import com.daon.identityx.entity.Audit;
import com.daon.identityx.entity.AuditAction;
import com.daon.identityx.entity.Session;
import com.daon.identityx.exception.ProcessingException;
import com.daon.identityx.fido.IIdentityXServices;
import com.daon.identityx.repository.AccountRepository;
import com.daon.identityx.repository.AuditRepository;
import com.daon.identityx.repository.SessionRepository;

/***
 * This class contains another REST interface which can be used in testing to retrieve additional information
 * from the Sample application.
 * 
 * These operations are not required by the app but are provided strictly for the purpose of debugging and
 * investigating the behaviour of the application.
 * 
 * @author Daon
 *
 */
@Controller
@RequestMapping("/test")
public class TestController {

	private static final Logger logger = LoggerFactory.getLogger(TestController.class);

	@Autowired
	private AccountRepository accountRepository;
	@Autowired
	private AuditRepository auditRepository;
	@Autowired
	private SessionRepository sessionRepository;
	@Autowired
	private IIdentityXServices fidoServices;

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
	 * This operation is only to allow for testing with an UNAUTHENTICATED REST client.
	 * It returns details of the account requested.
	 * 
	 * @param anId
	 * @return
	 */
	@RequestMapping(value = "accounts/{id}", method = RequestMethod.GET)
	@ResponseStatus(value = HttpStatus.OK)
	public @ResponseBody Account getAccount(@PathVariable("id") String anId) {

		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.GET_ACCOUNT);
		anAudit.setAccountId(anId);
		try {
			Account account = this.getAccountRepository().findById(anId);
			if (account == null) {
				throw new ProcessingException(Error.ACCOUNT_NOT_FOUND);
			}
			return account;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
		}
	}


	/***
	 * UNPROTECTED OPERATION - No session is required to perform this operation
	 * This operation is only to allow for testing with an UNAUTHENTICATED REST client.
	 * Returns a list of accounts managed by the system.
	 * 
	 * @param email
	 * @return
	 */
	@RequestMapping(value = "accounts", method = RequestMethod.GET)
	@ResponseStatus(value = HttpStatus.OK)
	public @ResponseBody Page<Account> getAccounts(@RequestParam("email") String email) {

		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.GET_ACCOUNTS);
		try {
			if (email == null || email.length() == 0) {
				email = "*";
			}
			email = email.replace('*', '%');
			Page<Account> accounts = this.getAccountRepository().findByEmailLike(email, null);
			return accounts;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
		}
	}

	/***
	 * UNPROTECTED OPERATION - No session is required to perform this operation
	 * This operation is only to allow for testing with an UNAUTHENTICATED REST client.
	 * Allows the specified account to be deleted.
	 * 
	 * @param email
	 */
	@RequestMapping(value = "accounts", method = RequestMethod.DELETE)
	@ResponseStatus(value = HttpStatus.OK)
	public void deleteAccountByEmail(@RequestParam("email") String email) {

		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.DELETE_ACCOUNT);
		try {
			Account account = this.getAccountRepository().findByEmail(email);
			if (account == null) {
				throw new ProcessingException(Error.ACCOUNT_NOT_FOUND);
			}
			anAudit.setAccountId(account.getId());
			this.getAccountRepository().delete(account);
			this.getFidoServices().deleteUser(email);
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
		}
	}

	/***
	 * UNPROTECTED OPERATION - No session is required to perform this operation
	 * This operation is only to allow for testing with an UNAUTHENTICATED REST client.
	 * Returns a list of sessions.
	 * 
	 * @param id
	 * @return
	 */
	@RequestMapping(value = "sessions", method = RequestMethod.GET)
	@ResponseStatus(value = HttpStatus.OK)
	public @ResponseBody Page<Session> getSessions(@RequestParam("id") String id) {

		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.GET_SESSIONS);
		try {
			if (id == null || id.length() == 0) {
				id = "*";
			}
			id = id.replace('*', '%');

			Page<Session> sessions = this.getSessionRepository().findByIdLike(id, null);
			return sessions;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
		}
	}

	/***
	 * UNPROTECTED OPERATION - No session is required to perform this operation
	 * This operation is only to allow for testing with an UNAUTHENTICATED REST client.
	 * Returns a list of audit records.
	 * 
	 * @param createdBefore
	 * @return
	 */
	@RequestMapping(value = "audits", method = RequestMethod.GET)
	@ResponseStatus(value = HttpStatus.OK)
	public @ResponseBody Page<Audit> getAudits(@RequestParam("createdBefore") Timestamp createdBefore) {

		long start = System.currentTimeMillis();
		Audit anAudit = new Audit(AuditAction.GET_AUDITS);
		try {
			Page<Audit> audits = this.getAuditRepository().findByCreatedDTMBefore(createdBefore, null);
			return audits;
		} finally {
			anAudit.setDuration(System.currentTimeMillis() - start);
			anAudit.setCreatedDTM(new Timestamp(System.currentTimeMillis()));
			this.getAuditRepository().save(anAudit);
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

	public IIdentityXServices getFidoServices() {
		return fidoServices;
	}

	public void setFidoServices(IIdentityXServices fidoServices) {
		this.fidoServices = fidoServices;
	}

}