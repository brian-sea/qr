const passport = require('passport')

const config = require('./config-defaults.js')

const OAuthProviders = { }

for( const provider in config.oauth2){
  const oauth = config.oauth2[provider];

  // provide is incomplete so skip it
  if( !oauth.clientID || !oauth.clientSecret || !oauth.callbackURL){
    continue;
  }

  /**
   * Maps the service specific fields to those the server needs
   * @param {Object} profile the service specific profile (passed in via main server)
   * @returns an object mapping the service specific fields to those needed by the server
   */
  let mapFields = function(profile){
    return {}
  }
  let fullCallbackURL = config.app.baseURL + oauth.callbackURL;
    
  if( provider === 'google' ) {
    // Google
    let GoogleStrategy = require('passport-google-oauth20').Strategy;

    passport.use(new GoogleStrategy({
        clientID: oauth.clientID,
        clientSecret: oauth.clientSecret,
        callbackURL: fullCallbackURL
      },
      function(accessToken, refreshToken, profile, done) {
        done(null, profile)
      }
    ));

    mapFields = function(profile){
      return {
        id: profile.id,
        name: profile.displayName,
        username: profile.emails[0].value,
      }
    }
  }
  else if( provider === 'github' ){
    // GitHub
    let GithubStrategy = require('passport-github').Strategy
    passport.use(new GithubStrategy({
        clientID: oauth.clientID,
        clientSecret: oauth.clientSecret,
        callbackURL: fullCallbackURL
      },
      function( accessToken, refreshToken, profile, done){
        done(null, profile);
      }
    ));    
    mapFields = function(profile) {
      return { 
        id: profile.id,
        name: profile.displayName,
        username: profile.username,
      }
    }
  }

  OAuthProviders[provider] = {
    name: oauth.name,
    callbackURL: oauth.callbackURL,
    provider,
    mapFields
  }
}

module.exports = OAuthProviders;
