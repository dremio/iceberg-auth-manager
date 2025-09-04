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
package com.dremio.iceberg.authmgr.oauth2.test.junit;

import com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Modifier;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junitpioneer.jupiter.cartesian.CartesianArgumentsSource;
import org.junitpioneer.jupiter.cartesian.CartesianParameterArgumentsProvider;

/**
 * A JUnit 5 cartesian test parameter annotation that provides a stream of values from an
 * "Enum-like" type.
 *
 * <p>This annotation can be used with any type that exposes a set of public static final constants,
 * and has a `getValue()` method that returns the constant's canonical value.
 *
 * <p>This is the case for many Nimbus SDK types, such as {@link GrantType} and {@link
 * ClientAuthenticationMethod}.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@CartesianArgumentsSource(EnumLikeMethodArgumentsProvider.class)
public @interface EnumLike {

  String[] includes() default {};

  String[] excludes() default {};
}

class EnumLikeMethodArgumentsProvider implements CartesianParameterArgumentsProvider<Object> {

  @Override
  public Stream<Object> provideArguments(ExtensionContext context, Parameter parameter) {
    EnumLike ann = parameter.getAnnotation(EnumLike.class);
    return enumLikeConstants(parameter)
        .filter(
            value ->
                ann.includes().length == 0
                    || Stream.of(ann.includes()).anyMatch(n -> nameMatches(n, value)))
        .filter(
            value ->
                ann.excludes().length == 0
                    || Stream.of(ann.excludes())
                        .noneMatch(name -> name.equalsIgnoreCase(value.toString())));
  }

  private Stream<Object> enumLikeConstants(Parameter parameter) {
    Class<?> type = parameter.getType();
    if (type.equals(GrantType.class)) {
      return ConfigUtils.SUPPORTED_INITIAL_GRANT_TYPES.stream().map(Object.class::cast);
    } else if (type.equals(ClientAuthenticationMethod.class)) {
      return ConfigUtils.SUPPORTED_CLIENT_AUTH_METHODS.stream()
          // In unit tests, we don't support (yet) JWS-based authentication methods
          .filter(method -> !ConfigUtils.requiresJwsAlgorithm(method))
          .map(Object.class::cast);
    } else {
      return Arrays.stream(type.getFields())
          .filter(
              f ->
                  f.getModifiers() == (Modifier.PUBLIC | Modifier.STATIC | Modifier.FINAL)
                      && f.getType().equals(type))
          .map(
              f -> {
                try {
                  return f.get(null);
                } catch (IllegalAccessException e) {
                  throw new RuntimeException(e);
                }
              });
    }
  }

  private boolean nameMatches(String s, Object constant) {
    try {
      String value = (String) constant.getClass().getMethod("getValue").invoke(constant);
      return s.equals(value);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
