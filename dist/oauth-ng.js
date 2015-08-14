/* oauth-ng - v0.3.0 - 2015-06-11 */
//This directive indicates executing the rest of this js file in 
//strict modus (see further http://www.w3schools.com/js/js_strict.asp)
'use strict';

// App libraries
var app = angular.module('oauth', [
  'oauth.directive',      // login directive
  'oauth.accessToken',    // access token service
  'oauth.endpoint',       // oauth endpoint service
  'oauth.resfreshpoint',  // oauth refresh service
  'oauth.profile',        // profile model
  'oauth.interceptor'     // bearer token interceptor
]);

angular.module('oauth').config(['$locationProvider','$httpProvider',
  function($locationProvider, $httpProvider) {
    $httpProvider.interceptors.push('ExpiredInterceptor');
  }]);


var accessTokenService = angular.module('oauth.accessToken', ['ngStorage']);

accessTokenService.factory('AccessToken', function($rootScope, $location, $localStorage, $sessionStorage, $interval){

    var service = {
            token: null,
            refresh_semaphore: true
        },
        oAuth2HashTokens = [ 
            ////per http://tools.ietf.org/html/rfc6749#section-4.2.2
            // and http://tools.ietf.org/html/rfc6749#section-4.1.4
            'access_token', 'refresh_token', 'id_token',
            'token_type', 'expires_in', 'scope', 'state',
            'error', 'error_description'
        ]
        ;
    /**
     * Returns the access token.
     */
    service.get = function(){
        return this.token;
    };

    /**
     * Sets and returns the access token. It tries (in order) the following strategies:
     * - takes the token from the fragment URI
     * - takes the token from the localStorage
     */
    service.set = function(){
        this.setTokenFromString($location.hash());

        //If hash is present in URL always use it, cuz its coming from oAuth2 provider redirect
        if(null === service.token){
            setTokenFromSession();
        }

        return this.token;
    };
    
    
    service.getAuthHeader = function(){
        if(this.token){
            return {
                Authorization : 'Bearer ' + this.token.access_token
            }
        }else{
            return {};
        }
    }
    
    /**
     * Returns the refresh semaphore.
     */
    service.getSemaphore = function(){
        return this.refresh_semaphore;
    };

    /**
     * Sets and returns the access token. It tries (in order) the following strategies:
     * - takes the token from the fragment URI
     * - takes the token from the localStorage
     */
    service.setSemaphore = function(sem){
        if (arguments.length){
            this.refresh_semaphore = sem;
            setSemaphoreInSession(sem);
            return sem;
        }

        //If hash is present in URL always use it, cuz its coming from oAuth2 provider redirect
        if(null === service.refresh_semaphore){
            var set_from_session = setSemaphoreFromSession();
            if (!set_from_session){
                this.refresh_semaphore = true;
            }
        }

        return this.refresh_semaphore;
    };
    
    /**
     * Delete the access token and remove the session.
     * @returns {null}
     */
    service.destroy = function(){
        delete $localStorage.token;
        delete $localStorage.refresh_semaphore;
        this.token = null;
        this.refresh_semaphore = true;
        return null;
    };

    /**
     * Tells if the access token is expired.
     */
    service.expired = function(){
        return (this.token && this.token.expires_at && this.token.expires_at<new Date());
    };

    /**
     * Get the access token from a string and save it
     * @param hash
     */
    service.setTokenFromString = function(hash){
        var params = getTokenFromString(hash);

        if(params){
            removeFragment();
            setToken(params);
            setExpiresAt();
            $rootScope.$broadcast('oauth:login', service.token);
        }
    };
    
    /**
     * Get the access token from a JSON struct and save it
     * @param params
     */
    service.setTokenFromStruct = function(params, decrypt){
        if(params){
            if(CryptoJS){
                var key = $sessionStorage.encrypt_key;
                delete $sessionStorage.encrypt_key;
                if (decrypt) {
                    var CryptoJSAesJson = {
                        stringify: function (cipherParams) {
                            var j = {ct: cipherParams.ciphertext.toString(CryptoJS.enc.Base64)};
                            if (cipherParams.iv) j.iv = cipherParams.iv.toString();
                            if (cipherParams.salt) j.s = cipherParams.salt.toString();
                            return JSON.stringify(j);
                        },
                        parse: function (jsonStr) {
                            var j = JSON.parse(jsonStr);
                            var cipherParams = CryptoJS.lib.CipherParams.create({ciphertext: CryptoJS.enc.Base64.parse(j.ct)});
                            if (j.iv) cipherParams.iv = CryptoJS.enc.Hex.parse(j.iv);
                            if (j.s) cipherParams.salt = CryptoJS.enc.Hex.parse(j.s);
                            return cipherParams;
                        }
                    }; 
                    
                    var auth_enc_words = CryptoJS.enc.Base64.parse(params);//auth_enc_64
                    params = auth_enc_words.toString(CryptoJS.enc.Utf8);//auth_enc
                    var decrypted_words = CryptoJS.AES.decrypt(params, key, {format: CryptoJSAesJson});
                    params = JSON.parse(decrypted_words.toString(CryptoJS.enc.Utf8));
                }
            }
            setToken(params);
            setExpiresAt();
            $rootScope.$broadcast('oauth:login', service.token);
        }
    };

    service.getEcryptionKey = function (prefix, resetkey) {
        if(!prefix) prefix = '';
        if (!$sessionStorage.encrypt_key || resetkey) {
            var encrypt_key = '';
            var key_length = 20;
            var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            var i;
            for (i = 0; i < key_length ;i++) {
                encrypt_key += chars[Math.round(Math.random() * 25)];
            }
            $sessionStorage.encrypt_key = prefix+encrypt_key;
        }

        return $sessionStorage.encrypt_key;
    };
            
    
   
    /* * * * * * * * * *
     * PRIVATE METHODS *
     * * * * * * * * * */

 
    /**
     * Set the access token.
     *
     * @param params
     * @returns {*|{}}
     */
    var setToken = function(params){
        params = checkParams(params);
        service.token = service.token || {};    // init the token
        angular.extend(service.token, params);  // set the access token params
        setTokenInSession();                    // save the token into the session
        setExpiresAtEvent();                    // event to fire when the token expires
        service.setSemaphore(true);
        return service.token;
    };

    /**
     * Parse the fragment URI and return an object
     * @param hash
     * @returns {{}}
     */
    var getTokenFromString = function(hash){
        var params = {},
            regex = /([^&=]+)=([^&]*)/g,
            m;

        while (m = regex.exec(hash)) {
            params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
        }

        if (params.access_token || params.error) {
            return params;
        }
    };

    /**
     * Save the access token into the session
     */
    var setTokenInSession = function(){
        $localStorage.token = service.token;
    };

    /**
     * Set the access token from the localStorage.
     */
    var setTokenFromSession = function(){
        if($localStorage.token){
            var params = $localStorage.token;
            params.expires_at = new Date(params.expires_at);
            setToken(params);
        }
    };
    
    var setSemaphoreInSession = function(sem){
        $localStorage.refresh_semaphore = sem;
    };
    
    var setSemaphoreFromSession = function(){
        if (typeof $localStorage.refresh_semaphore != 'undefined') {
            this.refresh_semaphore = $localStorage.refresh_semaphore;
            return true;
        };
        return false;
    };
    
    /**
     * Set the access token expiration date (useful for refresh logics)
     */
    var setExpiresAt = function(){
        if(service.token){
            var expires_at = new Date();
            expires_at.setSeconds(expires_at.getSeconds()+parseInt(service.token.expires_in)-60); // 60 seconds less to secure browser and response latency
            service.token.expires_at = expires_at;
        }
    };

    /**
     * Set the timeout at which the expired event is fired
     */
    var setExpiresAtEvent = function(){
        var time = (new Date(service.token.expires_at))-(new Date());
        if(time){
            $interval(function(){
                $rootScope.$broadcast('oauth:expired', service.token)
            }, time, 1)
        }
    };

    /**
     * Remove the oAuth2 pieces from the hash fragment
     */
    var removeFragment = function(){
        var curHash = $location.hash();
        angular.forEach(oAuth2HashTokens,function(hashKey){
            var re = new RegExp('&'+hashKey+'(=[^&]*)?|^'+hashKey+'(=[^&]*)?&?');
            curHash = curHash.replace(re,'');
        });

        $location.hash(curHash);
    };
    
    /**
     * Allow only the oAuth2 pieces in the params struct
     * @param params
     * $returns {{}}
     */
    
    var checkParams = function(params){
        var checkedParams = {};
        angular.forEach(oAuth2HashTokens,function(hashKey){
            if(params[hashKey]) checkedParams[hashKey] = params[hashKey];
        });
        return checkedParams;
    };

    return service;
});


var endpointClient = angular.module('oauth.endpoint', []);

endpointClient.factory('Endpoint', function(AccessToken, $location) {

  var service = {};
  var url;

  /*
   * Defines the authorization URL
   */

  service.set = function(params) {
    var oAuthScope = (params.scope) ? params.scope : '',
        state = (params.state) ? encodeURIComponent(params.state) : '',
        accessType = (params.accessType) ? params.accessType : '',
        approvalPrompt = (params.approvalPrompt)? true:false;
    if (params.fullsite) {
        var authPathHasQuery = ((params.fullsite.indexOf('?') == -1) ? false : true),
            //if authorizePath has ? already, append OAuth2 params
            appendChar = (authPathHasQuery ? '&' : '?');
            url = params.fullsite + appendChar + 'state=' + state;
    } else {
        var authPathHasQuery = (params.authorizePath.indexOf('?') == -1) ? false : true,
            //if authorizePath has ? already, append OAuth2 params
            appendChar = (authPathHasQuery) ? '&' : '?';
            url = params.site +
              params.authorizePath +
              appendChar + 'response_type='+params.responseType+'&' +
              'client_id=' + encodeURIComponent(params.clientId) + '&' +
              'redirect_uri=' + encodeURIComponent(params.redirectUri) + '&' +
              'scope=' + oAuthScope + '&' +
              'state=' + state + '&' +
              'access_type='+ accessType;
        if(approvalPrompt) url += '&approval_prompt=force';
    }
    return url;
  };

  /*
   * Returns the authorization URL
   */

  service.get = function() {
    return url;
  };


  /*
   * Redirects the app to the authorization URL
   */

  service.redirect = function() {
    window.location.replace(url);
  };

  return service;
});

var refreshPointClient = angular.module('oauth.resfreshpoint', []);

refreshPointClient.factory('RefreshPoint', function(AccessToken) {

  var service = {};
  var url;
  /*
   * Defines the refresh URL
   */

  service.set = function(params) {
    var state = (params.state) ? encodeURIComponent(params.state) : '';
    //If the uri has '?' already, just append params.
    var appendChar = (params.refreshUri.indexOf('?') == -1) ? '?' : '&';
    url = params.refreshUri + appendChar + 'state=' + state+'&' + 'refresh_token=';
    return url;
  };

  /*
   * Returns the refresh URL
   */

  service.get = function() {
    var tokens = AccessToken.get();
    if (tokens && tokens.refresh_token){
        return url + tokens.refresh_token;
    } else {
        return '';
    }
  };

  return service;
});


var profileClient = angular.module('oauth.profile', [])

profileClient.factory('Profile', function($http, AccessToken, $rootScope) {
  var service = {};
  var profile;

  service.find = function(uri) {
    var promise = $http.get(uri, { headers: headers() });
    promise.success(function(response) {
        profile = response;
        $rootScope.$broadcast('oauth:profile', profile);
    });
    return promise;
  };

  service.get = function(uri) {
    return profile;
  };

  service.set = function(resource) {
    profile = resource;
    return profile;
  };

  var headers = function() {
    return { Authorization: 'Bearer ' + AccessToken.get().access_token };
  };

  return service;
});


var interceptorService = angular.module('oauth.interceptor', 
    ['http-auth-interceptor-buffer']);

interceptorService.factory('ExpiredInterceptor', ['$rootScope', '$q', '$injector',
    'AccessToken', 'RefreshPoint', 'httpBuffer',
    function ($rootScope, $q, $injector, AccessToken, RefreshPoint, httpBuffer) {

        var service = {};
        
        service.responseError = function (response) {
            if (response.status === 401) {
                var refresh_url = RefreshPoint.get();
                //The refresh_url will be empty if there is no refresh key available
                //In that case there is no need at all to even try to do a refresh
                
                /*
                 * if refresh url
                 *      var $http
                 *      var $deferred
                 *      push on httpbuffer
                 *      if getSemaphore {
                 *          try refresh
                 *              on success: retry all from http buffer
                 *              //Note all subsequent calls will be after store 
                 *              //token in sessionband so they will use the new 
                 *              //token and not fail
                 *      } else 
                 *         
                 *      }
                 *      
                 */
                
                if (refresh_url) {
                    var deferred = $q.defer();
                    var original_config = response.config;
                    httpBuffer.append(original_config, deferred, true);
                    
                    if (AccessToken.getSemaphore()){
                        //If a refresh is already going on, it makes no sense to do another one
                        //and also, if that one failed or the refresh token is empty
                        //we can signal it like this, until a successfull token set 
                        //is retrieved in which case the 'semaphore is released'
                        //This release also happens upon session destroy (logout for
                        //example).
                        AccessToken.setSemaphore(false);
                        
                        var refresh_config = {
                            method: 'GET',
                            url: refresh_url,
                            is_refresh: true
                        };
                        var $http = $injector.get('$http');
                        $http(refresh_config).success(function(refresh_result){
                            var new_tokens = false;
                            if (refresh_result) {
                                if (refresh_result.tokens_enc) {
                                    new_tokens = true;
                                    AccessToken.setTokenFromStruct(refresh_result.tokens_enc, true);
                                } else if(refresh_result.tokens) {
                                    new_tokens = true;
                                    AccessToken.setTokenFromStruct(refresh_result.tokens, false);
                                }
                            }

                            if (new_tokens) {
                                httpBuffer.retryAll();
                            } else {
                                AccessToken.destroy();
                                $rootScope.$broadcast('oauth:logout');
                                httpBuffer.rejectAll('Refresh failed: no new tokens retrieved, probably erroneous output from refresh server');
                            }
                        }).error(function(error_str) {
                            AccessToken.destroy();
                            httpBuffer.rejectAll('failed: '+ error_str);
                            $rootScope.$broadcast('oauth:logout');
                        });
                    } else {
                        console.log('The request was denied for so long because the user was no'+
                           ' longer logged in and there is an attempt to refresh the session' +
                           ' going on. This call will be attempted later upon success.');
                    }
                    
                    return deferred.promise;
                } else {
                    console.log('The request was denied because the user was no'+
                       ' longer logged in and no refresh token was found .');
                }
            }
            return $q.reject(response);
            
        };
        
        service.request = function (config) {
            if (AccessToken.getSemaphore() || config.is_refresh){
               if(!config.headers) config.headers = {};
                angular.extend(config.headers, AccessToken.getAuthHeader());
                return config;
            }else {
                var deferred = $q.defer();
                httpBuffer.append(config, deferred, false);
                return deferred.promise;
            }
        };
        return service;
    }]);


/**
 * Private module, a utility, required internally by 'http-auth-interceptor'.
 */
angular.module('http-auth-interceptor-buffer', [])

.factory('httpBuffer', ['AccessToken', '$injector', function (AccessToken, $injector) {
    // from: https://github.com/witoldsz/angular-http-auth/blob/master/src/http-auth-interceptor.js
    /** Holds all the requests, so they can be re-requested in future. */
    var buffer = [];

    /** Service initialized later because of circular dependency problem. */
    var $http;

    function retryHttpRequest(config, deferred) {
        function successCallback(response) {
            deferred.resolve(response);
        }
        function errorCallback(response) {
            deferred.reject(response);
        }
        $http = $http || $injector.get('$http');
        $http(config).then(successCallback, errorCallback);
    }

    return {
        /**
         * Appends HTTP request configuration object with deferred response attached to buffer.
         */
        append: function (config, deferred, resend) {
            if (!resend)
                resend = false;
            buffer.push({
                config: config,
                deferred: deferred,
                resend: resend
            });
        },
        /**
         * Abandon or reject (if reason provided) all the buffered requests.
         */
        rejectAll: function (reason) {
            if (reason) {
                for (var i = 0; i < buffer.length; ++i) {
                    buffer[i].deferred.reject(reason);
                }
            }
            buffer = [];
        },
        /**
         * Retries all the buffered requests clears the buffer.
         */
        retryAll: function (updater) {
            for (var i = 0; i < buffer.length; ++i) {
                if (buffer[i].resend) {
                    if (updater)
                        buffer[i].config = updater(buffer[i].config);
                    retryHttpRequest(buffer[i].config, buffer[i].deferred);
                } else {
                    if (updater)
                        updater(buffer[i].config);

                    if (!buffer[i].config.headers)
                        buffer[i].config.headers = {};
                    angular.extend(buffer[i].config.headers, AccessToken.getAuthHeader());
                    buffer[i].deferred.resolve(buffer[i].config);
                }
            }
            buffer = [];
        }
    };
}]);

var directives = angular.module('oauth.directive', []);

directives.directive('oauth', function(AccessToken, Endpoint, RefreshPoint, Profile, $location, $rootScope, $compile, $http, $templateCache) {

  var definition = {
    restrict: 'AE',
    replace: true,
    scope: {
      fullsite: '@',      // (optional) this overrules all settings
      site: '@',          // (required) set the oauth server host (e.g. http://oauth.example.com)
      clientId: '@',      // (required) client id
      redirectUri: '@',   // (required) client redirect uri
      refreshUri: '@',    // (required) client refresh uri
      responseType: '@',  // (optional) response type, defaults to token (use 'token' for implicit flow and 'code' for authorization code flow
      scope: '@',         // (optional) scope
      profileUri: '@',    // (optional) user profile uri (e.g http://example.com/me)
      template: '@',      // (optional) template to render (e.g bower_components/oauth-ng/dist/views/templates/default.html)
      text: '@',          // (optional) login text
      authorizePath: '@', // (optional) authorization url
      state: '@',          // (optional) An arbitrary unique string created by your app to guard against Cross-site Request Forgery
      accessType: '@',
      approvalPrompt: '@'
    }
  };

  definition.link = function postLink(scope, element, attrs) {
    scope.show = 'none';

    scope.$watch('clientId', function(value) { init() });

    var init = function() {
      initAttributes();          // sets defaults
      compile();                 // compiles the desired layout
      Endpoint.set(scope);       // sets the oauth authorization url
      AccessToken.set(scope);    // sets the access token object (if existing, from fragment or session)
      RefreshPoint.set(scope);
      initProfile(scope);        // gets the profile resource (if existing the access token)
      initView();                // sets the view (logged in or out)
    };

    var initAttributes = function() {
        
      scope.fullsite      = scope.fullsite      || undefined;
      scope.authorizePath = scope.authorizePath || '/oauth/authorize';
      scope.tokenPath     = scope.tokenPath     || '/oauth/token';
      scope.template      = scope.template      || 'bower_components/oauth-ng/dist/views/templates/default.html';
      scope.text          = scope.text          || 'Sign In';
      scope.state         = scope.state         || undefined;
      scope.scope         = scope.scope         || undefined;
      scope.accessType    = scope.accessType    || undefined;
      scope.approvalPrompt = (scope.approvalPrompt === 'force')?true:false;
      
    };

    var compile = function() {
      $http.get(scope.template, { cache: $templateCache }).success(function(html) {
        element.html(html);
        $compile(element.contents())(scope);
      });
    };

    var initProfile = function(scope) {
      var token = AccessToken.get();
      
      if (! scope.profileUri){
          return true;
      }
      if (token && token.access_token) {
        Profile.find(scope.profileUri).success(function(response) {
          if (! response || !response.user_code){
              scope.profile = null;
              scope.logout();
          } else {
              scope.profile = response;
          }
        }).error( function(response){
            scope.profile = null;
            scope.logout();
        });
      } else if (scope.show == 'logged-in') {
            scope.logout();
      } else {
         
      }
    };

    var initView = function() {
      var token = AccessToken.get();

      if (!token)             { return loggedOut()  }  // without access token it's logged out
      if (token.access_token) { return authorized() }  // if there is the access token we are done
      if (token.error)        { return denied()     }  // if the request has been denied we fire the denied event
    };

    scope.login = function() {
      Endpoint.redirect();
    };

    scope.logout = function() {
      AccessToken.destroy(scope);
      loggedOut();
    };

    // user is authorized
    var authorized = function() {
      $rootScope.$broadcast('oauth:authorized', AccessToken.get());
      scope.show = 'logged-in';
    };

    // set the oauth directive to the logged-out status
    var loggedOut = function() {
      $rootScope.$broadcast('oauth:logout');
      scope.show = 'logged-out';
    };

    // set the oauth directive to the denied status
    var denied = function() {
      scope.show = 'denied';
      $rootScope.$broadcast('oauth:denied');
    };

    // Updates the template at runtime
    scope.$on('oauth:template:update', function(event, template) {
      scope.template = template;
      compile(scope);
    });

    // Hack to update the directive content on logout
    // TODO think to a cleaner solution
    scope.$on('$routeChangeSuccess', function () {
      init();
    });
  };

  return definition;
});
