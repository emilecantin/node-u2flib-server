/**
 * This is a command-line interface to the library.
 */

var u2f = require('./lib/u2f.js');
var program = require('commander');

var APP_ID = "http://test.emilecantin.com";
// var APP_ID = "http://demo.yubico.com";


program.option('-i, --app-id <string>', 'The application ID (eg.: http://foo.example.com)');
program.command('register-start')
  .description('Start the registration process. Outputs the registration challenge JSON.')
  .action(function() {
    var challenge = u2f.startRegistration(program.appId);

    // challenge.json
    console.log(JSON.stringify(challenge));
  });

program.command('register-end <challengePath> <responsePath>')
  .description('Finish the registration process. Outputs the completed registration JSON.')
  .action(function(challengePath, responsePath) {
    var challenge = require(challengePath);
    var response = require(responsePath);

    var registration = u2f.finishRegistration(challenge, response);

    // registration.json
    console.log(JSON.stringify(registration));
  });

program.command('authenticate-start <registrationPath>')
  .description('Start the authentication process. Outputs the authentication challenge JSON.')
  .action(function(registrationPath) {
    var registration = require(registrationPath);

    var authentication_challenge = u2f.startAuthentication(program.appId, registration);

    // authentication_challenge.json
    console.log(JSON.stringify(authentication_challenge));
  });

program.command('authenticate-end <challengePath> <responsePath> <registrationPath>')
  .description('Finish the authentication process. Outputs ????.')
  .action(function(challengePath, responsePath, registrationPath) {
    var challenge = require(challengePath);
    var response = require(responsePath);
    var registration = require(registrationPath);

    var authentication_result = u2f.finishAuthentication(challenge, response, registration);

    console.log(authentication_result);
  });

program.parse(process.argv);
