var u2f = require('./lib/u2f.js');

var APP_ID = "http://test.emilecantin.com/app-identity";

var program = require('commander');

program.command('register-start').action(function() {
  var registration_challenge = u2f.startRegistration(APP_ID);

  // registration_challenge.json
  console.log(JSON.stringify(registration_challenge));
});

program.command('register-end').action(function() {
  registration_challenge = require('./registration_challenge.json');
  var registration_response = require('./registration_response.json');

  var registration = u2f.finishRegistration(registration_challenge, registration_response);

  // registration.json
  console.log(JSON.stringify(registration));
});

program.command('authenticate-start').action(function() {
  registration = require('./registration.json');

  var authentication_challenge = u2f.startAuthentication(APP_ID, registration);

  // authentication_challenge.json
  console.log(JSON.stringify(authentication_challenge));
});

program.parse(process.argv);
