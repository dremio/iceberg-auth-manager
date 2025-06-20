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

import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthentication;
import com.dremio.iceberg.authmgr.oauth2.auth.JwtSigningAlgorithm;
import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantCommonNames;

/** Configuration constants for OAuth2. */
public final class OAuth2Properties {

  public static final String PREFIX = "rest.auth.oauth2.";

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
     *   <li>{@value GrantCommonNames#CLIENT_CREDENTIALS}
     *   <li>{@value GrantCommonNames#PASSWORD}
     *   <li>{@value GrantCommonNames#AUTHORIZATION_CODE}
     *   <li>{@value GrantCommonNames#DEVICE_CODE}
     *   <li>{@value GrantCommonNames#TOKEN_EXCHANGE}
     * </ul>
     *
     * Optional, defaults to {@value GrantCommonNames#CLIENT_CREDENTIALS}.
     */
    public static final String GRANT_TYPE = PREFIX + "grant-type";

    /**
     * Client ID to use when authenticating against the OAuth2 server. Required, unless using the
     * {@linkplain #DIALECT Iceberg OAuth2 dialect}.
     */
    public static final String CLIENT_ID = PREFIX + "client-id";

    /**
     * The OAuth2 client authentication method to use. Valid values are:
     *
     * <ul>
     *   <li>{@code none}: the client does not authenticate itself at the token endpoint, because it
     *       is a public client with no client secret or other authentication mechanism.
     *   <li>{@code client_secret_basic}: client secret is sent in the HTTP Basic Authorization
     *       header.
     *   <li>{@code client_secret_post}: client secret is sent in the request body as a form
     *       parameter.
     *   <li>{@code client_secret_jwt}: client secret is used to sign a JWT token.
     *   <li>{@code private_key_jwt}: client authenticates with a JWT assertion signed with a
     *       private key.
     * </ul>
     *
     * The default is {@code client_secret_basic} if the client is private, or {@code none} if the
     * client is public.
     *
     * <p>This property is ignored when dialect is {@link Dialect#ICEBERG_REST} or when a
     * {@linkplain #TOKEN token} is provided.
     */
    public static final String CLIENT_AUTH = PREFIX + "client-auth";

    /**
     * Client secret to use when authenticating against the OAuth2 server. Required if the client is
     * private and is authenticated using the standard "client-secret" methods. If other
     * authentication methods are used, this property is ignored.
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
     * The OAuth2 dialect. Possible values are: {@link Dialect#STANDARD} and {@link
     * Dialect#ICEBERG_REST}.
     *
     * <p>If the Iceberg dialect is selected, the agent will behave exactly like the built-in OAuth2
     * manager from Iceberg Core. This dialect should only be selected if the token endpoint is
     * internal to the REST catalog server, and the server is configured to understand this dialect.
     *
     * <p>The Iceberg dialect's main differences from standard OAuth2 are:
     *
     * <ul>
     *   <li>Only {@value GrantCommonNames#CLIENT_CREDENTIALS} grant type is supported;
     *   <li>Token refreshes are done with the {@value GrantCommonNames#TOKEN_EXCHANGE} grant type;
     *   <li>Token refreshes are done with Bearer authentication, not Basic authentication;
     *   <li>Public clients are not supported, however client secrets without client IDs are
     *       supported;
     *   <li>Client ID and client secret are sent as request body parameters, and not as Basic
     *       authentication.
     * </ul>
     *
     * Optional. The default value is {@code iceberg_rest} if either {@value #TOKEN} is provided or
     * {@value #TOKEN_ENDPOINT} contains a relative URI, and {@code standard} otherwise.
     */
    public static final String DIALECT = PREFIX + "dialect";
  }

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
     * JwtSigningAlgorithm#HMAC_SHA512} if the authentication method is {@link
     * ClientAuthentication#CLIENT_SECRET_JWT}, or {@link JwtSigningAlgorithm#RSA_SHA512} if the
     * authentication method is {@link ClientAuthentication#PRIVATE_KEY_JWT}.
     *
     * <p>Algorithm names must match either the JWS name or the JCA name of the algorithm.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.1">RFC 7518 Section
     *     3.1</a>
     */
    public static final String ALGORITHM = PREFIX + "algorithm";

    /**
     * The path on the local filesystem to the private key to use for signing the client assertion
     * JWT. Required if the authentication method is {@link ClientAuthentication#PRIVATE_KEY_JWT}.
     * The file must be in PEM format; it may contain a private key, or a private key and a
     * certificate chain. Only the private key is used.
     */
    public static final String PRIVATE_KEY = PREFIX + "private-key";

    /**
     * Extra claims to include in the client assertion JWT. This is a prefix property, and multiple
     * values can be set, each with a different key and value.
     */
    public static final String EXTRA_CLAIMS_PREFIX = PREFIX + "extra-claims.";
  }

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

  public static final class ResourceOwner {

    public static final String PREFIX = OAuth2Properties.PREFIX + "resource-owner.";

    /**
     * Username to use when authenticating against the OAuth2 server. Required if using OAuth2
     * authentication and {@value GrantCommonNames#PASSWORD} grant type, ignored otherwise.
     */
    public static final String USERNAME = ResourceOwner.PREFIX + "username";

    /**
     * Password to use when authenticating against the OAuth2 server. Required if using OAuth2
     * authentication and the {@value GrantCommonNames#PASSWORD} grant type, ignored otherwise.
     */
    public static final String PASSWORD = ResourceOwner.PREFIX + "password";
  }

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
     * This is only used if the grant type to use is {@value GrantCommonNames#AUTHORIZATION_CODE}.
     *
     * <p>Optional; if not present, the server will listen on the loopback interface.
     */
    public static final String CALLBACK_BIND_HOST = AuthorizationCode.PREFIX + "callback-bind-host";

    /**
     * Port of the OAuth2 authorization code flow local web server.
     *
     * <p>The internal web server will listen for the authorization code callback on this port. This
     * is only used if the grant type to use is {@value GrantCommonNames#AUTHORIZATION_CODE}.
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
     * Defines how long the agent should wait for the authorization code flow to complete. In other
     * words, how long the agent should wait for the user to log in and authorize the application.
     * This is only used if the grant type to use is {@value GrantCommonNames#AUTHORIZATION_CODE}.
     * Optional, defaults to {@value #DEFAULT_TIMEOUT}.
     */
    public static final String TIMEOUT = AuthorizationCode.PREFIX + "timeout";

    public static final String DEFAULT_TIMEOUT = "PT5M";

    /**
     * Whether to enable PKCE (Proof Key for Code Exchange) for the authorization code flow. The
     * default is {@code true}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</a>
     */
    public static final String PKCE_ENABLED = AuthorizationCode.PREFIX + "pkce.enabled";

    /**
     * The PKCE transformation to use. The default is {@code S256}. This is only used if PKCE is
     * enabled.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636#section-4.2">RFC 7636 Section 4.2</a>
     */
    public static final String PKCE_TRANSFORMATION =
        AuthorizationCode.PREFIX + "pkce.transformation";
  }

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
     * Defines how long the agent should wait for the device code flow to complete. In other words,
     * how long the agent should wait for the user to log in and authorize the application. This is
     * only used if the grant type to use is {@value GrantCommonNames#DEVICE_CODE}. Optional,
     * defaults to {@value #DEFAULT_TIMEOUT}.
     */
    public static final String TIMEOUT = DeviceCode.PREFIX + "timeout";

    public static final String DEFAULT_TIMEOUT = "PT5M";

    /**
     * Defines how often the agent should poll the OAuth2 server for the device code flow to
     * complete. This is only used if the grant type to use is {@value
     * GrantCommonNames#DEVICE_CODE}. Optional, defaults to {@value #DEFAULT_POLL_INTERVAL}.
     */
    public static final String POLL_INTERVAL = DeviceCode.PREFIX + "poll-interval";

    public static final String DEFAULT_POLL_INTERVAL = "PT5S";
  }

  public static final class TokenExchange {

    public static final String PREFIX = OAuth2Properties.PREFIX + "token-exchange.";

    /**
     * For token exchanges only. A URI that indicates the target service or resource where the
     * client intends to use the requested security token. Optional.
     */
    public static final String RESOURCE = TokenExchange.PREFIX + "resource";

    /**
     * For token exchanges only. The logical name of the target service where the client intends to
     * use the requested security token. This serves a purpose similar to the resource parameter but
     * with the client providing a logical name for the target service.
     */
    public static final String AUDIENCE = TokenExchange.PREFIX + "audience";

    public static final String DEFAULT_SUBJECT_TOKEN = "current_access_token";

    /**
     * For token exchanges only. The subject token to exchange. This can take 2 kinds of values:
     *
     * <ul>
     *   <li>The value {@value #DEFAULT_SUBJECT_TOKEN}, if the agent should use its current access
     *       token;
     *   <li>An arbitrary token: in this case, the agent will always use the static token provided
     *       here.
     * </ul>
     *
     * The default is to use the current access token. Note: when using token exchange as the
     * initial grant type, no current access token will be available: in this case, a valid, static
     * subject token to exchange must be provided via configuration.
     */
    public static final String SUBJECT_TOKEN = TokenExchange.PREFIX + "subject-token";

    /**
     * For token exchanges only. The type of the subject token. Must be a valid URN. The default is
     * {@code urn:ietf:params:oauth:token-type:access_token}.
     *
     * <p>If the agent is configured to use its access token as the subject token, please note that
     * if an incorrect token type is provided here, the token exchange could fail.
     */
    public static final String SUBJECT_TOKEN_TYPE = TokenExchange.PREFIX + "subject-token-type";

    /**
     * For token exchanges only. The actor token to exchange. This can take 2 kinds of values:
     *
     * <ul>
     *   <li>The value {@value #DEFAULT_SUBJECT_TOKEN}, if the agent should use its current access
     *       token;
     *   <li>An arbitrary token: in this case, the agent will always use the static token provided
     *       here.
     * </ul>
     *
     * The default is to not include any actor token.
     */
    public static final String ACTOR_TOKEN = TokenExchange.PREFIX + "actor-token";

    /**
     * For token exchanges only. The type of the actor token. Must be a valid URN. The default is
     * {@code urn:ietf:params:oauth:token-type:access_token}.
     *
     * <p>If the agent is configured to use its access token as the actor token, please note that if
     * an incorrect token type is provided here, the token exchange could fail.
     */
    public static final String ACTOR_TOKEN_TYPE = TokenExchange.PREFIX + "actor-token-type";
  }

  public static final class Impersonation {

    public static final String PREFIX = OAuth2Properties.PREFIX + "impersonation.";

    /**
     * Whether to enable "impersonation" mode. If enabled, each access token obtained from the
     * OAuth2 server using the configured initial grant type will be exchanged for a new token,
     * using the token exchange grant type.
     */
    public static final String ENABLED = Impersonation.PREFIX + "enabled";

    /**
     * For impersonation only. The root URL of an alternate OpenID Connect identity issuer provider,
     * to use when exchanging tokens only.
     *
     * <p>Either this property or {@value #TOKEN_ENDPOINT} must be set.
     *
     * <p>Endpoint discovery is performed using the OpenID Connect Discovery metadata published by
     * the issuer. See <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID
     * Connect Discovery 1.0</a> for more information.
     */
    public static final String ISSUER_URL = Impersonation.PREFIX + "issuer-url";

    /**
     * For impersonation only. The URL of an alternate OAuth2 token endpoint to use when exchanging
     * tokens only.
     *
     * <p>Either this property or {@value #ISSUER_URL} must be set.
     */
    public static final String TOKEN_ENDPOINT = Impersonation.PREFIX + "token-endpoint";

    /** For impersonation only. The OAUth2 client ID to use. */
    public static final String CLIENT_ID = Impersonation.PREFIX + "client-id";

    /**
     * For impersonation only. The OAUth2 client authentication method to use. Valid values are:
     *
     * <ul>
     *   <li>{@code none}: the client does not authenticate itself at the token endpoint, because it
     *       is a public client with no client secret or other authentication mechanism.
     *   <li>{@code client_secret_basic}: client secret is sent in the HTTP Basic Authorization
     *       header.
     *   <li>{@code client_secret_post}: client secret is sent in the request body as a form
     *       parameter.
     *   <li>{@code client_secret_jwt}: client secret is used to sign a JWT token.
     *   <li>{@code private_key_jwt}: client authenticates with a JWT assertion signed with a
     *       private key.
     * </ul>
     *
     * The default is {@code client_secret_basic} if the client is private, or {@code none} if the
     * client is public.
     */
    public static final String CLIENT_AUTH = PREFIX + "client-auth";

    /**
     * For impersonation only. The OAUth2 client secret to use. Must be set if the client is private
     * (confidential) and client authentication is done using a client secret.
     */
    public static final String CLIENT_SECRET = Impersonation.PREFIX + "client-secret";

    /**
     * For impersonation only. Space-separated list of scopes to include in each token exchange
     * request to the OAuth2 server. Optional.
     *
     * <p>The scope names will not be validated by the OAuth2 agent; make sure they are valid
     * according to <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">RFC 6749
     * Section 3.3</a>.
     */
    public static final String SCOPE = Impersonation.PREFIX + "scope";

    /**
     * Extra parameters to include in each request to the token endpoint, when using impersonation.
     * This is useful for custom parameters that are not covered by the standard OAuth2.0
     * specification.
     *
     * <p>This is a prefix property, and multiple values can be set, each with a different key and
     * value. The values must NOT be URL-encoded. Example:
     *
     * <pre>{@code
     * rest.auth.oauth2.impersonation.extra-params.custom_param1=custom_value1"
     * rest.auth.oauth2.impersonation.extra-params.custom_param2=custom_value2"
     * }</pre>
     */
    public static final String EXTRA_PARAMS_PREFIX = Impersonation.PREFIX + "extra-params.";
  }

  public static final class ImpersonationClientAssertion {

    public static final String PREFIX =
        OAuth2Properties.PREFIX + "impersonation.client-assertion.jwt.";

    /**
     * For impersonation only. The issuer of the client assertion JWT. Optional. The default is the
     * client ID.
     */
    public static final String ISSUER = PREFIX + "issuer";

    /**
     * For impersonation only. The subject of the client assertion JWT. Optional. The default is the
     * client ID.
     */
    public static final String SUBJECT = PREFIX + "subject";

    /**
     * For impersonation only. The audience of the client assertion JWT. Optional. The default is
     * the token endpoint.
     */
    public static final String AUDIENCE = PREFIX + "audience";

    /**
     * For impersonation only. The expiration time of the client assertion JWT. Optional. The
     * default is 5 minutes.
     */
    public static final String TOKEN_LIFESPAN = PREFIX + "token-lifespan";

    /**
     * For impersonation only. The signing algorithm to use for the client assertion JWT. Optional.
     * The default is {@link JwtSigningAlgorithm#HMAC_SHA512} if the authentication method is {@link
     * ClientAuthentication#CLIENT_SECRET_JWT}, or {@link JwtSigningAlgorithm#RSA_SHA512} if the
     * authentication method is {@link ClientAuthentication#PRIVATE_KEY_JWT}.
     *
     * <p>Algorithm names must match either the JWS name or the JCA name of the algorithm.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.1">RFC 7518 Section
     *     3.1</a>
     */
    public static final String ALGORITHM = PREFIX + "algorithm";

    /**
     * For impersonation only. The path on the local filesystem to the private key to use for
     * signing the client assertion JWT. Required if the authentication method is {@link
     * ClientAuthentication#PRIVATE_KEY_JWT}. The file must be in PEM format, and the first object
     * in the file must be a private key.
     */
    public static final String PRIVATE_KEY = PREFIX + "private-key";

    /**
     * For impersonation only. Extra claims to include in the client assertion JWT. This is a prefix
     * property, and multiple values can be set, each with a different key and value.
     */
    public static final String EXTRA_CLAIMS_PREFIX = PREFIX + "extra-claims.";
  }

  @SuppressWarnings("JavaLangClash")
  public static final class Runtime {

    public static final String PREFIX = OAuth2Properties.PREFIX + "runtime.";

    /**
     * The distinctive name of the OAuth2 agent. Defaults to {@value #DEFAULT_AGENT_NAME}. This name
     * is printed in all log messages and user prompts.
     */
    public static final String AGENT_NAME = Runtime.PREFIX + "agent-name";

    public static final String DEFAULT_AGENT_NAME = "iceberg-auth-manager";
  }

  public static final class Manager {

    public static final String PREFIX = OAuth2Properties.PREFIX + "manager.";

    /**
     * The session cache timeout. Cached sessions will become eligible for eviction after this
     * duration of inactivity. Defaults to {@value #DEFAULT_SESSION_CACHE_TIMEOUT}. Must be a valid
     * <a href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.
     *
     * <p>This value is used for housekeeping; it does not mean that cached sessions will stop
     * working after this time, but that the session cache will evict the session after this time of
     * inactivity. If the context is used again, a new session will be created and cached.
     */
    public static final String SESSION_CACHE_TIMEOUT = Manager.PREFIX + "session-cache-timeout";

    public static final String DEFAULT_SESSION_CACHE_TIMEOUT = "PT1H";

    /**
     * Whether to migrate Iceberg OAuth2 legacy properties. Defaults to {@code false}.
     *
     * <p>When enabled, the manager will automatically migrate legacy Iceberg OAuth2 properties to
     * their new equivalents; e.g. it would map {@code oauth2-server-uri} to {@link
     * Basic#TOKEN_ENDPOINT}.
     *
     * <p>When disabled, legacy properties are ignored.
     */
    public static final String MIGRATE_LEGACY_PROPERTIES =
        Manager.PREFIX + "migrate-legacy-properties";
  }

  private OAuth2Properties() {
    // empty
  }
}
