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

/***
 * The enum is used to record the actions performed at the REST interface.
 * 
 * @author Daon
 *
 */
public enum AuditAction {
	
	GET_ACCOUNT,
	GET_ACCOUNTS,
	CREATE_ACCOUNT,
	DELETE_ACCOUNT,
	CREATE_SESSION,
	DELETE_SESSION,
	GET_SESSIONS,
	REQUEST_REGISTRATION,
	CREATE_AUTH_REQUEST,
	CREATE_REG_REQUEST,
	CREATE_AUTHENTICATOR,
	GET_AUDITS,
	GET_FACETS,
	LIST_AUTHENTICATORS,
	GET_AUTHENTICATOR,
	DELETE_AUTHENTICATOR,
	CREATE_TRANSACTION_AUTH_REQUEST,
	VALIDATE_TRANSACTION_AUTH,
	GET_POLICY
}
