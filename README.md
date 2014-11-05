node-u2flib-server
==================

Serverside U2F library for Node.js. Provides functionality for registering U2F devices and authenticate with said devices.

This more or less a direct port of Yubico's server-side libraries for Java, PHP and Python (https://github.com/Yubico/java-u2flib-server and friends).

Installation
------------

```
npm install node-u2flib-server
```


Usage
-----

```
var u2f = require('node-u2flib-server');
```

The u2f protocol consists of two main actions:

- Registration, in which we associate a specific device with a user.
- Authentication, in which we verify that the user is in possesion of the previously registered device.

Each of these actions consist of two phases: challenge and response.

### Registration

To start registration, simply call:

```
/**
 * Initiates the registration of a device.
 *
 * @param appId the U2F AppID. Set this to the Web Origin of the login page, unless you need to
 * support logging in from multiple Web Origins. (Not supported for now)
 * @return a RegisterRequest, which should be sent to the client and temporary saved by the
 * server.
 */
var registerRequest = u2f.startRegistration('<YOUR_APP_ID>');
```

This will give a RegisterRequest object (see https://fidoalliance.org/specs/fido-u2f-javascript-api-v1.0-rd-20141008.pdf, section 4.1.1), suitable to use with client-side libraries. It should be kept around temporarily, because it is needed to finish the registration process.

Once the client has responded with a RegisterResponse object (see https://fidoalliance.org/specs/fido-u2f-javascript-api-v1.0-rd-20141008.pdf, section 4.1.2), you can call:

```
/**
 * Finishes a previously started registration.
 *
 * @param registerRequest The request previously sent to the client.
 * @param registerResponse The response from the device/client.
 * @return a DeviceRegistration object, holding information about the registered device. Servers should persist this.
 */
var deviceRegistration = u2f.finishRegistration(registerRequest, registerResponse);
```
This will either throw an exception with an error code (see the Errors section) if there is an error during validation of the RegisterResponse, or return a DeviceRegistration object. The DeviceRegistration object shoud be persisted on the server, as it's needed for future authentications. Its structure is the following:

```
{
  keyHandle: '', // A variable-length base64 string.
  publicKey: '', // A 65-byte base64 string.
  certificate: ''// A variable-length PEM-encoded certificate. It is not needed for future operations, but it validates the issuer of the authentication device. You may validate it if you want.
}
```

### Authentication

The authentication process mirrors relatively closely the registration process. To start an authentication, call:

```
/**
 * Initiates the authentication process.
 *
 * @param appId the U2F AppID. Set this to the Web Origin of the login page, unless you need to
 * support logging in from multiple Web Origins.
 * @param deviceRegistration the DeviceRegistration for which to initiate authentication.
 * @return a SignRequest which should be sent to the client and temporary saved by
 * the server.
 */
var signRequest = u2f.startAuthentication(appId, deviceRegistration);
```
This will give a SignRequest object (again, see https://fidoalliance.org/specs/fido-u2f-javascript-api-v1.0-rd-20141008.pdf, section 4.2.1), suitable to use with client-side libraries. Again, it should be kept around temporarily, because it is needed to finish the authentication process.

Once the client has responded with a SignResponse object (see https://fidoalliance.org/specs/fido-u2f-javascript-api-v1.0-rd-20141008.pdf, section 4.2.2), you can call:

```
/**
 * Finishes a previously started authentication.
 *
 * @param signRequest The challenge sent to the client.
 * @param signResponse The response from the device/client.
 * @param deviceRegistration the DeviceRegistration for which the authentication was initiated.
 * @return Some information about the authentication
 */
var deviceAuthentication = u2f.finishAuthentication(signRequest, signResponse, deviceRegistration);
```

This will either throw an exception with an error code (see the Errors section) if there is an error during validation of the SignResponse, or return a DeviceAuthentication object. The DeviceAuthentication object shoud be persisted on the server, as it's needed for future authentications. Its structure is the following:

```
{
  userPresence: '', // Should always be 1, meaning the presence of the user has been verified
  counter: '' // A counter that counts the number of authentications made by the device. Used to detect device cloning. You should check that it is increasing.
}
```

### Errors

The following errors can be thrown:

```
{
  registration: { // Registration errors
    NO_CLIENT_DATA: 101,
    NO_TYPE: 102,
    WRONG_TYPE: 103,
    CHALLENGE_MISMATCH: 104,
    NO_REGISTRATION_DATA: 105,
    WRONG_RESERVED_BYTE: 106,
    PUBLIC_KEY_ERROR: 107,
    SIGNATURE_INVALID: 108,
  },
  authentication: { // Authentication errors
    NO_KEY_HANDLE: 201,
    NO_CLIENT_DATA: 202,
    NO_SIGNATURE_DATA: 203,
    WRONG_KEY_HANDLE: 204,
    NO_TYPE: 205,
    WRONG_TYPE: 206,
    CHALLENGE_MISMATCH: 207,
    SIGNATURE_INVALID: 208,
  }
};
```

They are all exposed under `u2f.errors`.

Roadmap / Development
---------------------

- Add unit tests
- Refactor a bit
- Add a web server example?

