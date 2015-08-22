// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library implicit_grant;

typedef Future<Map<String, String>> GetResponse();
typedef Future<Void> RedirectUserAgent(Uri authorizationUrl) ;

const _EXPIRATION_GRACE = 10;

Future<Client> implicitGrant(
    Uri authorizationEndpoint,
    String clientId,
    String clientSecret,
    {List<String> scopes: const [],
    Uri redirectUri,
    RedirectUserAgent redirectUserAgent,
    String state,
    GetResponse getResponse,
    bool useBasicAuth: true,
    http.Client httpClient}) async {

  var startTime = new DateTime.now();
  var parameters = {"grant_type": "implicit"};
  var headers = {};

  if(clientId != null){
    if(useBasicAuth){
      headers['authorization'] = 'Basic ' +
      CryptoUtils.bytesToBase64(UTF8.encode('$clientId:$clientSecret'));
    }else {
      parameters['client_id'] = clientId;
      parameters['client_secret'] = clientSecret;
    }
  }

  if(state != null) parameters['state'] = state;
  if(redirectUri != null) parameters['redirect_uri']= redirectUri;
  if (!scopes.isEmpty) parameters['scope'] = scopes.join(' ');

  var url = addQueryParameters(authorizationEndpoint, parameters);

  await redirectUserAgent(url);
  var response = await getResponse();
  return _handleAuthorizationResponse(response);

}

Future<Client> _handleAuthorizationResponse(Uri authorizationEndpoint, Map<String, String> parameters) {

    if (parameters.containsKey('error')) {
      var description = parameters['error_description'];
      var uriString = parameters['error_uri'];
      var uri = uriString == null ? null : Uri.parse(uriString);
      throw new AuthorizationException(parameters['error'], description, uri);
    }

    if (_stateString != null) {
      _expectPresent(authorizationEndpoint,'state', parameters);
      } else if (parameters['state'] != _stateString) {
        throw new FormatException('Invalid OAuth response for '
        '"$authorizationEndpoint": parameter "state" expected to be '
        '"$_stateString", was "${parameters['state']}".');
      }


    _expectPresent(authorizationEndpoint, 'access_token', parameters);
    _expectPresent(authorizationEndpoint, 'token_type', parameters);


    var scope = parameters['scope'];
    if (scope != null) scopes = scope.split(" ");

    var expiration = expiresIn == null ? null :
    startTime.add(new Duration(seconds: expiresIn - _EXPIRATION_GRACE));

    var credentials = new Credentials(
        parameters['access_token'],
        parameters['refresh_token'],
        tokenEndpoint,
        scopes,
        expiration
        );

  return new Client(clientId, clientSecret, credentials);

}

_expectPresent(Uri authorizationEndpoint, String key, Map<String, String> response){
  if (!response.containsKey(key))
    throw new FormatException('Invalid OAuth response for '
    '"$authorizationEndpoint": parameter "$key" was missing.');

}

