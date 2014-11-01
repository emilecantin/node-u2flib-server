var crypto = require('crypto');
var challengeGenerator = require('./crypto/random_challenge_generator.js');

// Constants
var U2F_VERSION = "U2F_V2";
var PUBKEY_LEN = 65;


/**
 * Initiates the registration of a device.
 *
 * @param appId the U2F AppID. Set this to the Web Origin of the login page, unless you need to
 * support logging in from multiple Web Origins.
 * @return a StartedRegistration, which should be sent to the client and temporary saved by the
 * server.
 */
exports.startRegistration = function(appId) {
  var challenge = challengeGenerator.generateChallenge();
  return {
    version: U2F_VERSION,
    appId: appId,
    challenge: challenge,
  };
};

/**
 * Finishes a previously started registration.
 *
 * @param challenge The challenge sent to the client.
 * @param deviceResponse The response from the device/client.
 * @return a DeviceRegistration object, holding information about the registered device. Servers should
 * persist this.
 */
exports.finishRegistration = function(challenge, deviceResponse){
  if (deviceResponse.clientData) {
    var rawClientData = (new Buffer(deviceResponse.clientData, 'base64')).toString();
    var clientData = JSON.parse(rawClientData);
    if (clientData.typ === "navigator.id.finishEnrollment") {
      console.error("Type OK");
    }
    if (clientData.challenge === challenge.challenge) {
      console.error("Challenge OK");
    }
  }
  if (deviceResponse.registrationData) {
    var registration = {};
    var offset = 0

    var registrationData = new Buffer(deviceResponse.registrationData, 'base64');
    // Read reserved byte
    var reservedByte = registrationData.readInt8(offset++);
    if (reservedByte === 0x05) {
      console.error("Reserved byte OK");
    }
    // Read public key
    var publicKey = registrationData.slice(offset, offset + PUBKEY_LEN);
    var tmpKey = pubKeyToPem(publicKey);
    if (tmpKey) {
      console.error("Public key OK");
      registration.publicKey = publicKey.toString('base64');
    }
    offset += PUBKEY_LEN;
    // Read key handle
    var keyHandleLength = registrationData.readUInt8(offset++);
    var keyHandle = registrationData.slice(offset, offset+keyHandleLength);
    registration.keyHandle = keyHandle.toString('base64');
    offset += keyHandleLength;
    // Read certificate
    // length of certificate is stored in byte 3 and 4 (excluding the first 4 bytes)
    var certificateLength = 4;
    certificateLength += (registrationData.readUInt8(offset + 2) << 8);
    certificateLength += (registrationData.readUInt8(offset + 3) << 0);
    var rawCertificate = registrationData.slice(offset, offset+certificateLength);
    var pemCertificate = certToPem(rawCertificate);
    registration.certificate = pemCertificate;
    offset += certificateLength;
    // Read signature
    var signature = registrationData.slice(offset);
    var dataToVerify = "00";
    var appIdHasher = crypto.createHash('sha256');
    appIdHasher.update(challenge.appId);
    dataToVerify += appIdHasher.digest('hex');
    var clientDataHasher = crypto.createHash('sha256');
    clientDataHasher.update(rawClientData);
    dataToVerify += clientDataHasher.digest('hex');
    dataToVerify += keyHandle.toString('hex');
    dataToVerify += publicKey.toString('hex');
    dataToVerify = new Buffer(dataToVerify, 'hex')

    var verifier = crypto.createVerify('sha256');
    verifier.update(dataToVerify);
    var is_valid = verifier.verify(pemCertificate, signature);
    if(is_valid) {
      console.error("Signature OK");
      return registration;
    } else {
      return null;
    }


  }

};

/**
 * Initiates the authentication process.
 *
 * @param appId the U2F AppID. Set this to the Web Origin of the login page, unless you need to
 * support logging in from multiple Web Origins.
 * @param deviceRegistration the DeviceRegistration for which to initiate authentication.
 * @return a StartedAuthentication which should be sent to the client and temporary saved by
 * the server.
 */
exports.startAuthentication = function(appId, deviceRegistration){
  var challenge = challengeGenerator.generateChallenge();
  return {
    version: U2F_VERSION,
    appId: appId,
    keyHandle: deviceRegistration.keyHandle.replace('+', '-').replace('/', '_'),
    challenge: challenge.replace('+', '-').replace('/', '_')
  };
};

/**
 * Finishes a previously started authentication.
 *
 * @param challenge The challenge sent to the client.
 * @param deviceResponse The response from the device/client.
 * @param deviceRegistration the DeviceRegistration for which the authentication was initiated.
 * @param response the response from the device/client.
 */
exports.finishAuthentication = function(challenge, deviceResponse, deviceRegistration){
};

var pubKeyToPem = function(key) {
  if(key.length !== 65 || key[0] !== 0x04) {
    console.error("Key NOT OK!");
    console.error(key.length);
    console.error(key[0]);
    return;
  }
  /*
   * Convert the public key to binary DER format first
   * Using the ECC SubjectPublicKeyInfo OIDs from RFC 5480
   *
   *  SEQUENCE(2 elem)                        30 59
   *   SEQUENCE(2 elem)                       30 13
   *    OID1.2.840.10045.2.1 (id-ecPublicKey) 06 07 2a 86 48 ce 3d 02 01
   *    OID1.2.840.10045.3.1.7 (secp256r1)    06 08 2a 86 48 ce 3d 03 01 07
   *   BIT STRING(520 bit)                    03 42 ..key..
   */
  var der  = ""
  der += "3059";
  der += "3013";
  der += "06072a8648ce3d0201";
  der += "06082a8648ce3d030107";
  der += "0342" + key.toString("hex");

  var der_buf = new Buffer(der, 'hex');
  var der_64 = der_buf.toString('base64');

  var pem = "";
  pem  = "-----BEGIN PUBLIC KEY-----\n";
  while(der_64.length) {
    pem += der_64.slice(0, 64) + "\n";
    der_64 = der_64.slice(64);
  }
  pem += "-----END PUBLIC KEY-----";
  return pem;
};

var certToPem = function(cert_buf) {
  var cert_64 = cert_buf.toString('base64');

  var pem = "";
  pem += "-----BEGIN CERTIFICATE-----\n";
  while(cert_64.length) {
    pem += cert_64.slice(0, 64) + "\n";
    cert_64 = cert_64.slice(64);
  }
  pem += "-----END CERTIFICATE-----";
  return pem;
};
