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
package com.dremio.iceberg.authmgr.oauth2.flow;

/**
 * An interface representing an OAuth2 flow.
 *
 * <p>A flow is a short-lived component that represents a set of interactions (generally one, but
 * sometimes more) between the agent and the OAuth2 authorization server, in order to obtain access
 * tokens.
 *
 * @see InitialFlow
 * @see RefreshFlow
 */
public interface Flow {}
