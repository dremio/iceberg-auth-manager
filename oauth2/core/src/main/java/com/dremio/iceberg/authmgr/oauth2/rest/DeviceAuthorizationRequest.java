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
package com.dremio.iceberg.authmgr.oauth2.rest;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import jakarta.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import org.apache.iceberg.rest.RESTRequest;
import org.immutables.value.Value.Check;

/**
 * A device authorization request as defined in <a
 * href="https://tools.ietf.org/html/rfc8628#section-3.1">RFC 8628 Section 3.1</a>.
 *
 * <p>This request is used to request an authorization code for a device. The target endpoint is
 * typically the authorization server's device authorization endpoint.
 */
@AuthManagerImmutable
public abstract class DeviceAuthorizationRequest
    implements RESTRequest, ClientRequest, PostFormRequest {

  @Override
  @Check
  public final void validate() {}

  @Nullable
  public abstract String getScope();

  @Override
  public final Map<String, String> asFormParameters() {
    Map<String, String> data = new HashMap<>(ClientRequest.super.asFormParameters());
    if (getScope() != null) {
      data.put("scope", getScope());
    }
    return Map.copyOf(data);
  }

  public static Builder builder() {
    return ImmutableDeviceAuthorizationRequest.builder();
  }

  public interface Builder extends ClientRequest.Builder<DeviceAuthorizationRequest, Builder> {

    @CanIgnoreReturnValue
    Builder scope(String scope);

    DeviceAuthorizationRequest build();
  }
}
