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
package com.dremio.iceberg.authmgr.oauth2.http;

import com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils;
import com.dremio.iceberg.authmgr.oauth2.config.HttpConfig;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ReadOnlyHTTPRequest;
import com.nimbusds.oauth2.sdk.http.ReadOnlyHTTPResponse;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.HttpsSupport;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.pool.PoolConcurrencyPolicy;
import org.apache.hc.core5.pool.PoolReusePolicy;
import org.apache.hc.core5.reactor.ssl.SSLBufferMode;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;

public class ApacheHttpClient implements HttpClient {

  private final CloseableHttpClient client;

  public ApacheHttpClient() {
    this(HttpClients.createDefault());
  }

  public ApacheHttpClient(HttpConfig config) {
    this(createApacheClientBuilder(config).build());
  }

  public ApacheHttpClient(CloseableHttpClient client) {
    this.client = client;
  }

  @Override
  public ReadOnlyHTTPResponse send(ReadOnlyHTTPRequest httpRequest) throws IOException {
    ClassicHttpRequest apacheRequest = toApacheRequest(httpRequest);
    return client.execute(apacheRequest, ApacheHttpClient::toNimbusResponse);
  }

  @Override
  public void close() {
    try {
      client.close();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static ClassicHttpRequest toApacheRequest(ReadOnlyHTTPRequest nimbusRequest) {
    URI uri = nimbusRequest.getURI();
    HTTPRequest.Method method = nimbusRequest.getMethod();

    ClassicHttpRequest apacheRequest =
        ClassicRequestBuilder.create(method.name()).setUri(uri).build();

    for (Map.Entry<String, List<String>> entry : nimbusRequest.getHeaderMap().entrySet()) {
      for (String headerValue : entry.getValue()) {
        apacheRequest.addHeader(entry.getKey(), headerValue);
      }
    }

    if (nimbusRequest.getBody() != null) {
      HttpEntity entity =
          new ByteArrayEntity(nimbusRequest.getBody().getBytes(StandardCharsets.UTF_8), null);
      apacheRequest.setEntity(entity);
    }

    return apacheRequest;
  }

  private static ReadOnlyHTTPResponse toNimbusResponse(ClassicHttpResponse apacheResponse)
      throws IOException {

    StatusLine statusLine = new StatusLine(apacheResponse);
    HTTPResponse nimbusResponse = new HTTPResponse(statusLine.getStatusCode());
    nimbusResponse.setStatusMessage(statusLine.getReasonPhrase());

    for (Header header : apacheResponse.getHeaders()) {
      nimbusResponse
          .getHeaderMap()
          .compute(
              header.getName(),
              (k, v) -> {
                if (v == null) {
                  v = new ArrayList<>();
                }
                v.add(header.getValue());
                return v;
              });
    }

    HttpEntity httpEntity = apacheResponse.getEntity();
    if (httpEntity != null) {
      String body;
      try {
        body = EntityUtils.toString(httpEntity);
      } catch (ParseException e) {
        throw new RuntimeException(e);
      }
      if (StringUtils.isNotBlank(body)) {
        nimbusResponse.setBody(body);
      }
    }
    return nimbusResponse;
  }

  public static HttpClientBuilder createApacheClientBuilder(HttpConfig config) {

    HttpClientBuilder builder =
        HttpClients.custom().useSystemProperties().disableAuthCaching().disableCookieManagement();

    List<BasicHeader> defaultHeaders =
        config.getHeaders().entrySet().stream()
            .map(e -> new BasicHeader(e.getKey(), e.getValue()))
            .collect(Collectors.toList());
    builder.setDefaultHeaders(defaultHeaders);

    PoolingHttpClientConnectionManagerBuilder connManager =
        PoolingHttpClientConnectionManagerBuilder.create()
            .useSystemProperties()
            .setPoolConcurrencyPolicy(PoolConcurrencyPolicy.STRICT)
            .setConnPoolPolicy(PoolReusePolicy.LIFO);

    connManager.setDefaultSocketConfig(
        SocketConfig.custom()
            .setTcpNoDelay(true)
            .setSoTimeout(Timeout.of(config.getReadTimeout()))
            .build());

    connManager.setDefaultConnectionConfig(
        ConnectionConfig.custom()
            .setTimeToLive(TimeValue.ofMinutes(5))
            .setValidateAfterInactivity(TimeValue.ofSeconds(10))
            .setConnectTimeout(Timeout.of(config.getConnectionTimeout()))
            .build());

    connManager.setMaxConnTotal(100);
    connManager.setMaxConnPerRoute(10);

    SSLContext sslContext;
    try {
      SSLContextBuilder sslContextBuilder = SSLContextBuilder.create();
      if (config.getSslTrustStorePath().isPresent()) {
        sslContextBuilder.loadTrustMaterial(
            config.getSslTrustStorePath().get(),
            config.getSslTrustStorePassword().map(String::toCharArray).orElse(null));
      } else if (config.isSslTrustAll()) {
        sslContextBuilder.loadTrustMaterial(TrustAllStrategy.INSTANCE);
      }
      sslContext = sslContextBuilder.build();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    connManager.setTlsSocketStrategy(
        new DefaultClientTlsStrategy(
            sslContext,
            config.getSslProtocols().isEmpty()
                ? HttpsSupport.getSystemProtocols()
                : ConfigUtils.parseCommaSeparatedList(config.getSslProtocols().get())
                    .toArray(new String[0]),
            config.getSslCipherSuites().isEmpty()
                ? HttpsSupport.getSystemCipherSuits()
                : ConfigUtils.parseCommaSeparatedList(config.getSslCipherSuites().get())
                    .toArray(new String[0]),
            SSLBufferMode.STATIC,
            config.isSslHostnameVerificationEnabled()
                ? HttpsSupport.getDefaultHostnameVerifier()
                : NoopHostnameVerifier.INSTANCE));

    builder.setConnectionManager(connManager.build());

    RequestConfig requestConfig =
        RequestConfig.custom()
            .setResponseTimeout(Timeout.of(config.getReadTimeout()))
            .setRedirectsEnabled(true)
            .setCircularRedirectsAllowed(false)
            .setMaxRedirects(5)
            .setContentCompressionEnabled(config.isCompressionEnabled())
            .build();

    builder.setDefaultRequestConfig(requestConfig);

    if (config.getProxyHost().isPresent() && config.getProxyPort().isPresent()) {
      HttpHost proxy = new HttpHost(config.getProxyHost().get(), config.getProxyPort().getAsInt());
      builder.setProxy(proxy);
      if (config.getProxyUsername().isPresent() && config.getProxyPassword().isPresent()) {
        BasicCredentialsProvider credentialProvider = new BasicCredentialsProvider();
        credentialProvider.setCredentials(
            new AuthScope(proxy),
            new UsernamePasswordCredentials(
                config.getProxyUsername().get(), config.getProxyPassword().get().toCharArray()));
        builder.setDefaultCredentialsProvider(credentialProvider);
      }
    }

    if (!config.isCompressionEnabled()) {
      builder.disableContentCompression();
    }

    return builder;
  }
}
