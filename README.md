# README

## Overview

This project implements a secure and functional bank API that supports user authentication, role-based access control, and account management. The following changes and enhancements were made to improve the security, functionality, and logging capabilities of the application.

---

## Security Fixes

1. **Password Hashing**:
   - Previously, passwords were stored in plain text, which is insecure.
   - Now, passwords are hashed using the `bcrypt` algorithm before being stored to ensure secure storage of user credentials.

2. **Duplicate Username Check**:
   - Added validation to prevent registering duplicate usernames during the `/register` process.

3. **JWT Token Expiry**:
   - Added an expiration time to the JWT tokens to prevent the misuse of stale or long-lived tokens.

4. **Sensitive Data Masking in Logs**:
   - Modified the logging mechanism to mask sensitive information like plain-text passwords and JWT tokens in both requests and responses.

5. **Authorization Validation**:
   - Added middleware to validate user roles and permissions before accessing protected API endpoints, ensuring proper role-based access control.

6. **Rate Limiting**:
   - Implemented rate limiting to mitigate brute-force attacks and abuse of the API.

---

## Logging Enhancements

1. **Access Logs**:
   - Implemented request and response logging in a structured JSON format.
   - Logs include request headers, query parameters, request body length, response body length, and HTTP status class.
   - improtant note about the logging. in deposit and withdraw cases i didnt add the user_id because it is not in the "qs_params": "<REQUEST_QUERY_STRING_PARAMS>" but in the request body payload.

2. **Error Logging**:
   - Added centralized error handling to ensure all application errors are logged uniformly with context for easier debugging.

---

## Functional Enhancements

1. **Implemented Main Function**:
   - Developed the `main` function to set up the API server using the `http` package to handle requests and route them to appropriate handlers.

2. **Added Middleware**:
   - Middleware for:
     - Request validation.
     - Role-based access control.
     - Logging all incoming requests and outgoing responses.

3. **Improved Token Generation**:
   - Enhanced the JWT generation mechanism to include expiration time and ensure tokens are invalidated when no longer needed.


## Instructions Followed

- **Security Improvements**:
  - Identified and fixed issues in the API, such as plain-text password storage and missing duplicate username checks.
  - Added middleware for access control and secure logging.

- **Logging**:
  - Implemented request and response logging in the required JSON format.

- **API Server**:
  - Developed the main function to serve the API using the `http` package.

## Permissions for API Endpoints

### /register
- **Permissions**: Public access.
- **Description**: Allows new users to register with a username and password. Duplicate username checks and password hashing are applied.

---

### /login
- **Permissions**: Public access.
- **Description**: Generates a JWT token upon successful authentication with a valid username and password.

---

### /balance
- **Permissions**: User-only access his own and admin can acccess for everyone.
- **Description**: Allows authenticated users to retrieve their account balance.

---

### /deposit
- **Permissions**: User-only access.
- **Description**: Enables users to deposit funds into their account.

---

### /withdraw
- **Permissions**: User-only access.
- **Description**: Allows users to withdraw funds from their account, with proper balance validation.

---

### /accounts
- **Permissions**: Admin-only access.
- **Description**: Grants admins the ability to list all user accounts.

---

### /create-account
- **Permissions**: Admin-only access.
- **Description**: Enables admins to create new accounts for users.



## Bonus:
- In test.txt, there are all the command prompts to test the API using curl. 
