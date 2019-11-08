"use strict";

/*
 * adonis-ally
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

const got = require("got");

const CE = require("../Exceptions");
const OAuth2Scheme = require("../Schemes/OAuth2");
const AllyUser = require("../AllyUser");
const utils = require("../../lib/utils");
const _ = require("lodash");

/**
 * Auth2i driver to authenticate users via OAuth2
 * scheme.
 *
 * @class Auth2i
 * @constructor
 */
class Auth2i extends OAuth2Scheme {
  constructor(Config) {
    const config = Config.get("services.ally.auth2i");

    utils.validateDriverConfig("auth2i", config);
    utils.debug("auth2i", config);

    super(config.clientId, config.clientSecret, config.headers);

    /**
     * Oauth specific values to be used when creating the redirect
     * url or fetching user profile.
     */
    this._redirectUri = config.redirectUri;
    this._redirectUriOptions = _.merge(
      { response_type: "code" },
      config.options
    );

    /**
     * Public scopes
     */
    this.scope = _.size(config.scope)
      ? config.scope
      : [
          "phone",
          "email",
          "openid",
          "aws.cognito.signin.user.admin",
          "profile"
        ];
  }

  /**
   * Injections to be made by the IoC container
   *
   * @attribute inject
   *
   * @return {Array}
   */
  static get inject() {
    return ["Adonis/Src/Config"];
  }

  /**
   * Returns a boolean telling if driver supports
   * state
   *
   * @method supportStates
   *
   * @return {Boolean}
   */
  get supportStates() {
    return true;
  }

  /**
   * Scope seperator for seperating multiple
   * scopes.
   *
   * @attribute scopeSeperator
   *
   * @return {String}
   */
  get scopeSeperator() {
    return "+";
  }

  /**
   * Base url to be used for constructing
   * facebook oauth urls.
   *
   * @attribute baseUrl
   *
   * @return {String}
   */
  get baseUrl() {
    return "https://auth2i.auth.us-east-1.amazoncognito.com/oauth2";
  }

  /**
   * Relative url to be used for redirecting
   * user.
   *
   * @attribute authorizeUrl
   *
   * @return {String} [description]
   */
  get authorizeUrl() {
    return "authorize";
  }

  /**
   * Relative url to be used for exchanging
   * access token.
   *
   * @attribute accessTokenUrl
   *
   * @return {String}
   */
  get accessTokenUrl() {
    return "token";
  }

  /**
   * Returns the user profile as an object using the
   * access token.
   *
   * @method _getUserProfile
   * @async
   *
   * @param   {String} accessToken
   *
   * @return  {Object}
   *
   * @private
   */
  async _getUserProfile(accessToken) {
    const profileUrl = `https://auth2i.auth.us-east-1.amazoncognito.com/oauth2/userInfo`;

    const response = await got(profileUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      },
      json: true
    });

    return response.body;
  }

  /**
   * Normalize the user profile response and build an Ally user.
   *
   * @param {object} userProfile
   * @param {object} accessTokenResponse
   *
   * @return {object}
   *
   * @private
   */
  _buildAllyUser(userProfile, accessTokenResponse) {
    const user = new AllyUser();
    const expires = _.get(accessTokenResponse, "result.expires_in");

    user
      .setOriginal(userProfile)
      .setFields(
        userProfile.sub,
        userProfile.name,
        userProfile.email
        // userProfile.avatar_url
      )
      .setToken(
        accessTokenResponse.accessToken,
        accessTokenResponse.refreshToken,
        null,
        expires ? Number(expires) : null
      );

    return user;
  }

  /**
   * Returns user primary and verified email address.
   *
   * @method _getUserEmail
   * @async
   *
   * @param   {String} accessToken
   *
   * @return  {String}
   *
   * @private
   */
  async _getUserEmail(accessToken) {
    const response = await got(
      `https://auth2i.auth.us-east-1.amazoncognito.com/oauth2/userInfo`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        },
        json: true
      }
    );
    return _.find(response.body, email => email.primary && email.verified)
      .email;
  }

  /**
   * Returns the redirect url for a given provider
   *
   * @method getRedirectUrl
   *
   * @param {String} [state]
   *
   * @return {String}
   */
  async getRedirectUrl(state) {
    const options = state
      ? Object.assign(this._redirectUriOptions, { state })
      : this._redirectUriOptions;
    return decodeURIComponent(
      this.getUrl(this._redirectUri, this.scope, options)
    );
  }

  /**
   * Parser error mentioned inside the result property
   * of the oauth response.
   *
   * @method parseProviderResultError
   *
   * @param  {Object} response
   *
   * @throws {OAuthException} If response has error property
   */
  parseProviderResultError(response) {
    const message = response.error_description || response.error;
    return CE.OAuthException.tokenExchangeException(message, null, response);
  }

  /**
   * Parses the redirect errors returned by auth2i
   * and returns the error message.
   *
   * @method parseRedirectError
   *
   * @param  {Object} queryParams
   *
   * @return {String}
   */
  parseRedirectError(queryParams) {
    return queryParams.error_description
      ? `${queryParams.error_description}. Learn more: ${queryParams.error_uri}`
      : "Oauth failed during redirect";
  }

  /**
   * Returns the user profile with it's access token, refresh token
   * and token expiry.
   *
   * @method getUser
   * @async
   *
   * @param {Object} queryParams
   * @param {String} [originalState]
   *
   * @return {Object}
   */
  async getUser(queryParams, originalState) {
    const code = queryParams.code;
    const state = queryParams.state;

    /**
     * Throw an exception when query string does not have
     * code.
     */
    if (!code) {
      const errorMessage = this.parseRedirectError(queryParams);
      throw CE.OAuthException.tokenExchangeException(
        errorMessage,
        null,
        errorMessage
      );
    }

    /**
     * Valid state with original state
     */
    if (state && originalState !== state) {
      throw CE.OAuthException.invalidState();
    }

    const accessTokenResponse = await this.getAccessToken(
      code,
      this._redirectUri,
      {
        grant_type: "authorization_code"
      }
    );

    const userProfile = await this._getUserProfile(
      accessTokenResponse.accessToken
    );
    return this._buildAllyUser(userProfile, accessTokenResponse);
  }

  /**
   *
   * @param {string} accessToken
   */
  async getUserByToken(accessToken) {
    const userProfile = await this._getUserProfile(accessToken);

    return this._buildAllyUser(userProfile, {
      accessToken,
      refreshToken: null
    });
  }
}

module.exports = Auth2i;
