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

package com.daon.identityx.controller.model;

/***
 * The class used to reply to a request with an error.  In general only the code and message are used
 * but it is possible that if the error occurs during the process of a FIDO specific operation then 
 * information should be passed to the FIDO client as well.
 * 
 * @author Daon
 *
 */
public class Error {

	public static Error UNEXPECTED_ERROR = new Error(1,"An unexpected error occurred.  Please see the log files.");
	public static Error METHOD_NOT_IMPLEMENTED = new Error(2,"The method has not been implemented");
	
	public static Error ACCOUNT_NOT_FOUND = new Error(10,"Account not found");
	public static Error INVALID_CREDENTIALS = new Error(11,"Invalid credentials provided - the user could not be authenticated");
	public static Error INSUFFICIENT_CREDENTIALS = new Error(12, "The user cannot be authenticated - please supply a username and password or a FIDO authentication response");
	public static Error AUTHENTICATION_REQUEST_TIMED_OUT = new Error(13,"The authentication request timed out - please retry.");
	public static Error UNKNOWN_AUTHENTICATOR = new Error(14,"This authenticator is not known by the server.");
	public static Error REVOKED_AUTHENTICATOR = new Error(15,"This authenticator has been deregistered.  It is no longer acceptable");

	
	public static Error AUTHENTICATION_REQUEST_ID_NOT_PROVIDED = new Error(100,"The authentication request ID must be provided");
	public static Error PASSWORD_NOT_PROVIDED = new Error(101,"The password must be provided");
	public static Error EMAIL_NOT_PROVIDED = new Error(102,"The email must be provided");
	public static Error FIRST_NAME_NOT_PROVIDED = new Error(103,"The first name must be provided");
	public static Error LAST_NAME_NOT_PROVIDED = new Error(104,"The last name must be provided");
	public static Error ACCOUNT_ALREADY_EXISTS = new Error(105,"An account with this email address already exists");
	
	public static Error FIDO_AUTH_COMPLETE_ACCOUNT_NOT_FOUND = new Error(200,"The user was authenticated by FIDO but this account is not in the system");
	public static Error UNKNOWN_SESSION_IDENTIFIER = new Error(201,"Unknown session identifier");
	public static Error EXPIRED_SESSION = new Error(202,"The specified session has expired");
	public static Error NON_EXISTENT_SESSION = new Error(203,"The specified session does not exist");
	
	public static Error TRANSACTION_CONTENT_NOT_PROVIDED = new Error(303,"Transaction data must be provided");
	
	private int code;
	private String message;
	private String fidoMessage;
	private Long fidoResponseCode;
	private String fidoResponseMsg;
	
	public Error() {
	}

	public Error(int code, String message) {
		this.code = code;
		this.message = message;
	}
	
	public int getCode() {
		return code;
	}

	public void setCode(int code) {
		this.code = code;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}
	
	public String toString() {
		return "Code: " + this.getCode() + " Message: " + this.getMessage();
	}

	public String getFidoMessage() {
		return fidoMessage;
	}

	public void setFidoMessage(String fidoMessage) {
		this.fidoMessage = fidoMessage;
	}

	public Long getFidoResponseCode() {
		return fidoResponseCode;
	}

	public void setFidoResponseCode(Long fidoResponseCode) {
		this.fidoResponseCode = fidoResponseCode;
	}

	public String getFidoResponseMsg() {
		return fidoResponseMsg;
	}

	public void setFidoResponseMsg(String fidoResponseMsg) {
		this.fidoResponseMsg = fidoResponseMsg;
	}

}
