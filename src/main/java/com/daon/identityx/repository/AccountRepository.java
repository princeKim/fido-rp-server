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

package com.daon.identityx.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.PagingAndSortingRepository;

import com.daon.identityx.entity.Account;

/***
 * Stores the accounts
 * 
 * @author Daon
 *
 */
public interface AccountRepository extends PagingAndSortingRepository<Account, String> {

    Page<Account> findByLastNameLike(String lastName, Pageable pageable);
    
    Page<Account> findByEmailLike(String email, Pageable pageable);
    
    Account findByEmail(String email);
    
    Account findById(String anId);
}