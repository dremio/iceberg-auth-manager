/*
 * Copyright (C) 2025 Dremio Corporation
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
package com.dremio.iceberg.authmgr.oauth2;

import com.dremio.iceberg.authmgr.oauth2.http.HttpClientType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

/** Configuration constants for OAuth2. */
public final class OAuth2Properties {

  public static final String PREFIX = "rest.auth.oauth2.";

  /**
   * Basic OAuth2 properties. These properties are used to configure the basic OAuth2 options such
   * as the issuer URL, token endpoint, client ID, and client secret.
   */
  public static final class Basic {

    /**
     * The initial access token to use. Optional. If this is set, the agent will not attempt to
     * fetch the first new token from the Authorization server, but will use this token instead.
     *
     * <p>This option is mostly useful when migrating from the Iceberg OAuth2 manager to this OAuth2
     * manager. Always prefer letting the agent fetch an initial token from the configured
     * Authorization server.
     *
     * <p>When this option is set, the token is not validated by the agent, and it's not always
     * possible to refresh it. It's recommended to use this option only for testing purposes, or if
     * you know that the token is valid and will not expire too soon.
     */
    public static final String TOKEN = PREFIX + "token";

    /**
     * OAuth2 issuer URL.
     *
     * <p>The root URL of the Authorization server, which will be used for discovering supported
     * endpoints and their locations. For Keycloak, this is typically the realm URL: {@code
     * https://<keycloak-server>/realms/<realm-name>}.
     *
     * <p>Two "well-known" paths are supported for endpoint discovery: {@code
     * .well-known/openid-configuration} and {@code .well-known/oauth-authorization-server}. The
     * full metadata discovery URL will be constructed by appending these paths to the issuer URL.
     *
     * <p>Either this property or {@link #TOKEN_ENDPOINT} must be set.
     *
     * @see <a
     *     href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID
     *     Connect Discovery 1.0</a>
     * @see <a href="https://tools.ietf.org/html/rfc8414#section-5">RFC 8414 Section 5</a>
     */
    public static final String ISSUER_URL = PREFIX + "issuer-url";

    /**
     * URL of the OAuth2 token endpoint. For Keycloak, this is typically {@code
     * https://<keycloak-server>/realms/<realm-name>/protocol/openid-connect/token}.
     *
     * <p>Either this property or {@link #ISSUER_URL} must be set. In case it is not set, the token
     * endpoint will be discovered from the {@link #ISSUER_URL issuer URL}, using the OpenID Connect
     * Discovery metadata published by the issuer.
     */
    public static final String TOKEN_ENDPOINT = PREFIX + "token-endpoint";

    /**
     * The grant type to use when authenticating against the OAuth2 server. Valid values are:
     *
     * <ul>
     *   <li>{@link GrantType#CLIENT_CREDENTIALS client_credentials}
     *   <li>{@link GrantType#PASSWORD password}
     *   <li>{@link GrantType#AUTHORIZATION_CODE authorization_code}
     *   <li>{@link GrantType#DEVICE_CODE urn:ietf:params:oauth:grant-type:device_code}
     *   <li>{@link GrantType#TOKEN_EXCHANGE urn:ietf:params:oauth:grant-type:token-exchange}
     * </ul>
     *
     * Optional, defaults to {@code client_credentials}.
     */
    public static final String GRANT_TYPE = PREFIX + "grant-type";

    /**
     * Client ID to use when authenticating against the OAuth2 server. Required, unless a
     * {@linkplain #TOKEN static token} is provided.
     */
    public static final String CLIENT_ID = PREFIX + "client-id";

    /**
     * The OAuth2 client authentication method to use. Valid values are:
     *
     * <ul>
     *   <li>{@link ClientAuthenticationMethod#NONE none}: the client does not authenticate itself
     *       at the token endpoint, because it is a public client with no client secret or other
     *       authentication mechanism.
     *   <li>{@link ClientAuthenticationMethod#CLIENT_SECRET_BASIC client_secret_basic}: client
     *       secret is sent in the HTTP Basic Authorization header.
     *   <li>{@link ClientAuthenticationMethod#CLIENT_SECRET_POST client_secret_post}: client secret
     *       is sent in the request body as a form parameter.
     *   <li>{@link ClientAuthenticationMethod#CLIENT_SECRET_JWT client_secret_jwt}: client secret
     *       is used to sign a JWT token.
     *   <li>{@link ClientAuthenticationMethod#PRIVATE_KEY_JWT private_key_jwt}: client
     *       authenticates with a JWT assertion signed with a private key.
     * </ul>
     *
     * The default is {@code client_secret_basic}.
     */
    public static final String CLIENT_AUTH = PREFIX + "client-auth";

    /**
     * Client secret to use when authenticating against the OAuth2 server. Required if the client is
     * private and is authenticated using the standard "client-secret" methods. If other
     * authentication methods are used (e.g. {@code private_key_jwt}), this property is ignored.
     */
    public static final String CLIENT_SECRET = PREFIX + "client-secret";

    /**
     * Space-separated list of scopes to include in each request to the OAuth2 server. Optional,
     * defaults to empty (no scopes).
     *
     * <p>The scope names will not be validated by the OAuth2 agent; make sure they are valid
     * according to <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">RFC 6749
     * Section 3.3</a>.
     */
    public static final String SCOPE = PREFIX + "scope";

    /**
     * Extra parameters to include in each request to the token endpoint. This is useful for custom
     * parameters that are not covered by the standard OAuth2.0 specification. Optional, defaults to
     * empty.
     *
     * <p>This is a prefix property, and multiple values can be set, each with a different key and
     * value. The values must NOT be URL-encoded. Example:
     *
     * <pre>{@code
     * rest.auth.oauth2.extra-params.custom_param1=custom_value1"
     * rest.auth.oauth2.extra-params.custom_param2=custom_value2"
     * }</pre>
     *
     * For example, Auth0 requires the {@code audience} parameter to be set to the API identifier.
     * This can be done by setting the following configuration:
     *
     * <pre>{@code
     * rest.auth.oauth2.extra-params.audience=https://iceberg-rest-catalog/api
     * }</pre>
     */
    public static final String EXTRA_PARAMS_PREFIX = PREFIX + "extra-params.";

    /**
     * Defines how long the agent should wait for tokens to be acquired. Optional, defaults to
     * {@value #DEFAULT_TIMEOUT}.
     */
    public static final String TIMEOUT = PREFIX + "timeout";

    public static final String DEFAULT_TIMEOUT = "PT5M";
  }

  /**
   * Configuration properties for JWT client assertion as specified in <a
   * href="https://datatracker.ietf.org/doc/html/rfc7523">JSON Web Token (JWT) Profile for OAuth 2.0
   * Client Authentication and Authorization Grants</a>.
   *
   * <p>These properties allow the client to authenticate using the {@code client_secret_jwt} or
   * {@code private_key_jwt} authentication methods.
   */
  public static final class ClientAssertion {

    public static final String PREFIX = OAuth2Properties.PREFIX + "client-assertion.jwt.";

    /** The issuer of the client assertion JWT. Optional. The default is the client ID. */
    public static final String ISSUER = PREFIX + "issuer";

    /** The subject of the client assertion JWT. Optional. The default is the client ID. */
    public static final String SUBJECT = PREFIX + "subject";

    /** The audience of the client assertion JWT. Optional. The default is the token endpoint. */
    public static final String AUDIENCE = PREFIX + "audience";

    /** The expiration time of the client assertion JWT. Optional. The default is 5 minutes. */
    public static final String TOKEN_LIFESPAN = PREFIX + "token-lifespan";

    /**
     * The signing algorithm to use for the client assertion JWT. Optional. The default is {@link
     * JWSAlgorithm#HS512} if the authentication method is {@link
     * ClientAuthenticationMethod#CLIENT_SECRET_JWT}, or {@link JWSAlgorithm#RS512} if the
     * authentication method is {@link ClientAuthenticationMethod#PRIVATE_KEY_JWT}.
     *
     * <p>Algorithm names must match the "alg" Param Value as described in <a
     * href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.1">RFC 7518 Section 3.1</a>.
     */
    public static final String ALGORITHM = PREFIX + "algorithm";

    /**
     * The path on the local filesystem to the private key to use for signing the client assertion
     * JWT. Required if the authentication method is {@link
     * ClientAuthenticationMethod#PRIVATE_KEY_JWT}. The file must be in PEM format; it may contain a
     * private key, or a private key and a certificate chain. Only the private key is used.
     */
    public static final String PRIVATE_KEY = PREFIX + "private-key";

    /**
     * Extra claims to include in the client assertion JWT. This is a prefix property, and multiple
     * values can be set, each with a different key and value.
     */
    public static final String EXTRA_CLAIMS_PREFIX = PREFIX + "extra-claims.";
  }

  /** Configuration properties for the token refresh feature. */
  public static final class TokenRefresh {

    public static final String PREFIX = OAuth2Properties.PREFIX + "token-refresh.";

    /**
     * Whether to enable token refresh. If enabled, the agent will automatically refresh its access
     * token when it expires. If disabled, the agent will only fetch the initial access token, but
     * won't refresh it. Defaults to {@code true}.
     */
    public static final String ENABLED = TokenRefresh.PREFIX + "enabled";

    /**
     * Default access token lifespan; if the OAuth2 server returns an access token without
     * specifying its expiration time, this value will be used. Note that when this happens, a
     * warning will be logged.
     *
     * <p>Optional, defaults to {@value #DEFAULT_ACCESS_TOKEN_LIFESPAN}. Must be a valid <a
     * href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.
     */
    public static final String ACCESS_TOKEN_LIFESPAN =
        TokenRefresh.PREFIX + "access-token-lifespan";

    public static final String DEFAULT_ACCESS_TOKEN_LIFESPAN = "PT5M";

    /**
     * Refresh safety window to use; a new token will be fetched when the current token's remaining
     * lifespan is less than this value. Optional, defaults to {@value #DEFAULT_SAFETY_WINDOW}. Must
     * be a valid <a href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.
     */
    public static final String SAFETY_WINDOW = TokenRefresh.PREFIX + "safety-window";

    public static final String DEFAULT_SAFETY_WINDOW = "PT10S";

    /**
     * Defines for how long the OAuth2 manager should keep the tokens fresh, if the agent is not
     * being actively used. Setting this value too high may cause an excessive usage of network I/O
     * and thread resources; conversely, when setting it too low, if the agent is used again, the
     * calling thread may block if the tokens are expired and need to be renewed synchronously.
     * Optional, defaults to {@value #DEFAULT_IDLE_TIMEOUT}. Must be a valid <a
     * href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.
     */
    public static final String IDLE_TIMEOUT = TokenRefresh.PREFIX + "idle-timeout";

    public static final String DEFAULT_IDLE_TIMEOUT = "PT30S";
  }

  /**
   * Configuration properties for the <a
   * href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.3">Resource Owner Password
   * Credentials Grant</a> flow.
   *
   * <p>Note: according to the <a
   * href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.4">OAuth
   * 2.0 Security Best Current Practice, section 2.4</a> this flow should NOT be used anymore
   * because it "insecurely exposes the credentials of the resource owner to the client".
   */
  public static final class ResourceOwner {

    public static final String PREFIX = OAuth2Properties.PREFIX + "resource-owner.";

    /**
     * Username to use when authenticating against the OAuth2 server. Required if using OAuth2
     * authentication and {@link GrantType#PASSWORD} grant type, ignored otherwise.
     */
    public static final String USERNAME = ResourceOwner.PREFIX + "username";

    /**
     * Password to use when authenticating against the OAuth2 server. Required if using OAuth2
     * authentication and the {@link GrantType#PASSWORD} grant type, ignored otherwise.
     */
    public static final String PASSWORD = ResourceOwner.PREFIX + "password";
  }

  /**
   * Configuration properties for the <a
   * href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">Authorization Code Grant</a>
   * flow.
   *
   * <p>This flow is used to obtain an access token by redirecting the user to the OAuth2
   * authorization server, where they can log in and authorize the client application to access
   * their resources.
   */
  public static final class AuthorizationCode {

    public static final String PREFIX = OAuth2Properties.PREFIX + "auth-code.";

    /**
     * URL of the OAuth2 authorization endpoint. For Keycloak, this is typically {@code
     * https://<keycloak-server>/realms/<realm-name>/protocol/openid-connect/auth}.
     *
     * <p>If using the "authorization_code" grant type, either this property or {@link
     * Basic#ISSUER_URL} must be set. In case it is not set, the authorization endpoint will be
     * discovered from the {@link Basic#ISSUER_URL issuer URL}, using the OpenID Connect Discovery
     * metadata published by the issuer.
     */
    public static final String ENDPOINT = AuthorizationCode.PREFIX + "endpoint";

    /**
     * The redirect URI. This is the value of the {@code redirect_uri} parameter in the
     * authorization code request.
     *
     * <p>Optional; if not present, the URL will be computed from {@value #CALLBACK_BIND_HOST},
     * {@value #CALLBACK_BIND_PORT} and {@value #CALLBACK_CONTEXT_PATH}.
     *
     * <p>Specifying this value is generally only necessary in containerized environments, if a
     * reverse proxy modifies the callback before it reaches the client, or if external TLS
     * termination is performed.
     */
    public static final String REDIRECT_URI = AuthorizationCode.PREFIX + "redirect-uri";

    /**
     * Address of the OAuth2 authorization code flow local web server.
     *
     * <p>The internal web server will listen for the authorization code callback on this address.
     * This is only used if the grant type to use is {@link GrantType#AUTHORIZATION_CODE}.
     *
     * <p>Optional; if not present, the server will listen on the loopback interface.
     */
    public static final String CALLBACK_BIND_HOST = AuthorizationCode.PREFIX + "callback-bind-host";

    /**
     * Port of the OAuth2 authorization code flow local web server.
     *
     * <p>The internal web server will listen for the authorization code callback on this port. This
     * is only used if the grant type to use is {@link GrantType#AUTHORIZATION_CODE}.
     *
     * <p>Optional; if not present, a random port will be used.
     */
    public static final String CALLBACK_BIND_PORT = AuthorizationCode.PREFIX + "callback-bind-port";

    /**
     * Context path of the OAuth2 authorization code flow local web server.
     *
     * <p>Optional; if not present, a default context path will be used.
     */
    public static final String CALLBACK_CONTEXT_PATH =
        AuthorizationCode.PREFIX + "callback-context-path";

    /**
     * Whether to enable PKCE (Proof Key for Code Exchange) for the authorization code flow. The
     * default is {@code true}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</a>
     */
    public static final String PKCE_ENABLED = AuthorizationCode.PREFIX + "pkce.enabled";

    /**
     * The PKCE code challenge method to use. The default is {@code S256}. This is only used if PKCE
     * is enabled.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636#section-4.2">RFC 7636 Section 4.2</a>
     */
    public static final String PKCE_METHOD = AuthorizationCode.PREFIX + "pkce.method";
  }

  /**
   * Configuration properties for the <a href="https://datatracker.ietf.org/doc/html/rfc8628">Device
   * Authorization Grant</a> flow.
   *
   * <p>This flow is used to obtain an access token for devices that do not have a browser or
   * limited input capabilities. The user is prompted to visit a URL on another device and enter a
   * code to authorize the device.
   */
  public static final class DeviceCode {

    public static final String PREFIX = OAuth2Properties.PREFIX + "device-code.";

    /**
     * URL of the OAuth2 device authorization endpoint. For Keycloak, this is typically {@code
     * http://<keycloak-server>/realms/<realm-name>/protocol/openid-connect/auth/device}.
     *
     * <p>If using the "Device Code" grant type, either this property or {@link Basic#ISSUER_URL}
     * must be set.
     */
    public static final String ENDPOINT = DeviceCode.PREFIX + "endpoint";

    /**
     * Defines how often the agent should poll the OAuth2 server for the device code flow to
     * complete. This is only used if the grant type to use is {@link GrantType#DEVICE_CODE}.
     * Optional, defaults to {@value #DEFAULT_POLL_INTERVAL}.
     */
    public static final String POLL_INTERVAL = DeviceCode.PREFIX + "poll-interval";

    public static final String DEFAULT_POLL_INTERVAL = "PT5S";
  }

  /**
   * Configuration properties for the <a href="https://datatracker.ietf.org/doc/html/rfc8693">Token
   * Exchange</a> flow.
   *
   * <p>This flow allows a client to exchange one token for another, typically to obtain a token
   * that is more suitable for the target resource or service.
   */
  public static final class TokenExchange {

    public static final String PREFIX = OAuth2Properties.PREFIX + "token-exchange.";

    /**
     * For token exchanges only. The subject token to exchange.
     *
     * <p>If this value is present, the subject token will be used as-is. If this value is not
     * present, the subject token will be dynamically fetched using the configuration provided under
     * the {@value #SUBJECT_CONFIG_PREFIX} prefix.
     */
    public static final String SUBJECT_TOKEN = TokenExchange.PREFIX + "subject-token";

    /**
     * For token exchanges only. The type of the subject token. Must be a valid URN. The default is
     * {@code urn:ietf:params:oauth:token-type:access_token}.
     */
    public static final String SUBJECT_TOKEN_TYPE = TokenExchange.PREFIX + "subject-token-type";

    /**
     * For token exchanges only. The actor token to exchange.
     *
     * <p>If this value is present, the actor token will be used as-is. If this value is not
     * present, the actor token will be dynamically fetched using the configuration provided under
     * the {@value #ACTOR_CONFIG_PREFIX} prefix. If no configuration is provided, no actor token
     * will be used.
     */
    public static final String ACTOR_TOKEN = TokenExchange.PREFIX + "actor-token";

    /**
     * For token exchanges only. The type of the actor token. Must be a valid URN. The default is
     * {@code urn:ietf:params:oauth:token-type:access_token}.
     *
     * <p>If the agent is configured to dynamically fetch the actor token, this property is ignored
     * since only access tokens can be dynamically fetched.
     */
    public static final String ACTOR_TOKEN_TYPE = TokenExchange.PREFIX + "actor-token-type";

    /**
     * For token exchanges only. The type of the requested security token. Must be a valid URN. The
     * default is {@code urn:ietf:params:oauth:token-type:access_token}.
     */
    public static final String REQUESTED_TOKEN_TYPE = TokenExchange.PREFIX + "requested-token-type";

    /**
     * For token exchanges only. The configuration to use for fetching the subject token. Required
     * if {@value #SUBJECT_TOKEN} is not set.
     *
     * <p>This is a prefix property; any property that can be set under the {@value
     * OAuth2Properties#PREFIX} prefix can also be set under this prefix.
     *
     * <p>The effective subject token fetch configuration will be the result of merging the
     * subject-specific configuration with the main configuration.
     *
     * <p>Example:
     *
     * <pre>{@code
     * rest.auth.oauth2.grant-type=token_exchange
     * rest.auth.oauth2.token-endpoint=https://main-token-endpoint.com/token
     * rest.auth.oauth2.client-id=main-client-id
     * rest.auth.oauth2.client-secret=main-client-secret
     * rest.auth.oauth2.token-exchange.subject-token.grant-type=client_credentials
     * rest.auth.oauth2.token-exchange.subject-token.client-id=subject-client-id
     * rest.auth.oauth2.token-exchange.subject-token.client-secret=subject-client-secret
     * }</pre>
     *
     * The above configuration will result in a token exchange where the subject token is obtained
     * using the client credentials grant type, with specific client ID and secret, but sharing the
     * token endpoint, client authentication method and other settings with the main agent.
     */
    public static final String SUBJECT_CONFIG_PREFIX = TokenExchange.PREFIX + "subject-token.";

    /**
     * For token exchanges only. The configuration to use for fetching the actor token. Optional;
     * required only if {@value #ACTOR_TOKEN} is not set but an actor token is required.
     *
     * <p>This is a prefix property; any property that can be set under the {@value
     * OAuth2Properties#PREFIX} prefix can also be set under this prefix.
     *
     * <p>The effective actor token fetch configuration will be the result of merging the
     * actor-specific configuration with the main configuration.
     *
     * <p>Example:
     *
     * <pre>{@code
     * rest.auth.oauth2.grant-type=token_exchange
     * rest.auth.oauth2.token-endpoint=https://main-token-endpoint.com/token
     * rest.auth.oauth2.client-id=main-client-id
     * rest.auth.oauth2.client-secret=main-client-secret
     * rest.auth.oauth2.token-exchange.actor-token.grant-type=client_credentials
     * rest.auth.oauth2.token-exchange.actor-token.client-id=actor-client-id
     * rest.auth.oauth2.token-exchange.actor-token.client-secret=actor-client-secret
     * }</pre>
     *
     * The above configuration will result in a token exchange where the actor token is obtained
     * using the client credentials grant type, with specific client ID and secret, but sharing the
     * token endpoint, client authentication method and other settings with the main agent.
     */
    public static final String ACTOR_CONFIG_PREFIX = TokenExchange.PREFIX + "actor-token.";

    /**
     * For token exchanges only. A space-separatee list of URIs that indicate the target service(s)
     * or resource(s) where the client intends to use the requested security token. Optional.
     */
    public static final String RESOURCE = TokenExchange.PREFIX + "resource";

    /**
     * For token exchanges only. A space-separated list of logical names of the target service(s)
     * where the client intends to use the requested security token. This serves a purpose similar
     * to the resource parameter but with the client providing a logical name for the target
     * service.
     */
    public static final String AUDIENCE = TokenExchange.PREFIX + "audience";
  }

  /**
   * Configuration properties for the whole system.
   *
   * <p>These properties are used to configure properties such as the session cache timeout and the
   * HTTP client type.
   */
  @SuppressWarnings("JavaLangClash")
  public static final class System {

    public static final String PREFIX = OAuth2Properties.PREFIX + "system.";

    /**
     * The distinctive name of the OAuth2 agent. Defaults to {@value #DEFAULT_AGENT_NAME}. This name
     * is printed in all log messages and user prompts.
     */
    public static final String AGENT_NAME = System.PREFIX + "agent-name";

    public static final String DEFAULT_AGENT_NAME = "iceberg-auth-manager";

    /**
     * The session cache timeout. Cached sessions will become eligible for eviction after this
     * duration of inactivity. Defaults to {@value #DEFAULT_SESSION_CACHE_TIMEOUT}. Must be a valid
     * <a href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.
     *
     * <p>This value is used for housekeeping; it does not mean that cached sessions will stop
     * working after this time, but that the session cache will evict the session after this time of
     * inactivity. If the context is used again, a new session will be created and cached.
     */
    public static final String SESSION_CACHE_TIMEOUT = System.PREFIX + "session-cache-timeout";

    public static final String DEFAULT_SESSION_CACHE_TIMEOUT = "PT1H";

    /**
     * The type of HTTP client to use for making HTTP requests to the OAuth2 server. Valid values
     * are:
     *
     * <ul>
     *   <li>{@link HttpClientType#DEFAULT default}: uses the built-in URLConnection-based client
     *       provided by the underlying OAuth2 library.
     * </ul>
     *
     * <p>Optional, defaults to {@code default}.
     */
    public static final String HTTP_CLIENT_TYPE = System.PREFIX + "http-client.type";
  }

  private OAuth2Properties() {
    // empty
  }
}
