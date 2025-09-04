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
package com.dremio.iceberg.authmgr.oauth2.docs;

import com.thoughtworks.qdox.JavaProjectBuilder;
import com.thoughtworks.qdox.model.JavaClass;
import com.thoughtworks.qdox.model.JavaField;
import com.thoughtworks.qdox.model.JavaMethod;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses the properties from the source code and generates documentation for them.
 *
 * <p>This generator is mostly intended to parse the `OAuth2Properties` class. The parser relies
 * heavily on conventions, such as the use of `PREFIX` fields, or fields starting with `DEFAULT_`,
 * or the presence of nested classes to structure the properties into sections.
 */
public class DocumentationGenerator {

  private static final Pattern CODE_PATTERN = Pattern.compile("\\{@code\\s(.+?)}");

  private static final Pattern REF_PATTERN =
      Pattern.compile("\\{@(?:link(?:plain)?|value)\\s+([^ }]+)( [^}]+)?}");

  private static final Pattern EXTERNAL_LINK_PATTERN =
      Pattern.compile("<a\\s+href=\"([^\"]+)\"[^>]*>([^<]+)</a>");

  private static final Pattern PRE_PATTERN =
      Pattern.compile("<pre>\\s*(?:\\{@code)?(.*?)(}\\s*)?</pre>", Pattern.DOTALL);

  private static final Map<String, String> KNOWN_REFS;

  static {
    Map<String, String> refs = new LinkedHashMap<>();
    refs.put("GrantType#CLIENT_CREDENTIALS", "client_credentials");
    refs.put("GrantType#PASSWORD", "password");
    refs.put("GrantType#AUTHORIZATION_CODE", "authorization_code");
    refs.put("GrantType#REFRESH_TOKEN", "refresh_token");
    refs.put("GrantType#DEVICE_CODE", "urn:ietf:params:oauth:grant-type:device_code");
    refs.put("GrantType#TOKEN_EXCHANGE", "urn:ietf:params:oauth:grant-type:token-exchange");
    refs.put("JWSAlgorithm#HS512", "HS512");
    refs.put("JWSAlgorithm#RS512", "RS512");
    refs.put("ClientAuthenticationMethod#NONE", "none");
    refs.put("ClientAuthenticationMethod#CLIENT_SECRET_BASIC", "client_secret_basic");
    refs.put("ClientAuthenticationMethod#CLIENT_SECRET_POST", "client_secret_post");
    refs.put("ClientAuthenticationMethod#CLIENT_SECRET_JWT", "client_secret_jwt");
    refs.put("ClientAuthenticationMethod#PRIVATE_KEY_JWT", "private_key_jwt");
    refs.put("HttpClientType#DEFAULT", "default");
    refs.put("HttpClientType#APACHE", "apache");
    KNOWN_REFS = Map.copyOf(refs);
  }

  private static final String ROOT_CLASS_NAME = "com.dremio.iceberg.authmgr.oauth2.OAuth2Config";

  private final Path rootConfigFile;
  private final String header;
  private final Path outputFile;

  private JavaProjectBuilder builder;
  private String rootPrefix;
  private Map<String, Section> sections;

  public static void main(String[] args) throws IOException {
    String sourceFile = args[0];
    String header = args[1];
    String outputFile = args[2];
    DocumentationGenerator generator =
        new DocumentationGenerator(Path.of(sourceFile), header, Path.of(outputFile));
    generator.run();
  }

  public DocumentationGenerator(Path rootConfigFile, String header, Path outputFile) {
    this.rootConfigFile = rootConfigFile;
    this.header = header;
    this.outputFile = outputFile;
  }

  public void run() throws IOException {
    parse();
    generate();
  }

  private void parse() throws IOException {

    builder = new JavaProjectBuilder();
    builder.addSource(rootConfigFile.toFile());

    File[] files =
        rootConfigFile
            .resolveSibling("config")
            .toFile()
            .listFiles(file -> file.getName().endsWith("Config.java"));
    for (File file : Objects.requireNonNull(files)) {
      builder.addSource(file);
    }

    JavaClass topClass = builder.getClassByName(ROOT_CLASS_NAME);
    rootPrefix =
        topClass.getFieldByName("PREFIX").getInitializationExpression().replace("\"", "") + '.';

    sections = new LinkedHashMap<>();

    for (JavaMethod method : topClass.getMethods()) {

      if (method.getAnnotations().stream()
          .map(a -> a.getType().getSimpleName())
          .noneMatch(
              n ->
                  n.equals("io.smallrye.config.WithName")
                      || n.equals("io.smallrye.config.WithParentName"))) {
        continue;
      }

      JavaClass sectionConfigClass = (JavaClass) method.getReturnType();

      sections.put(sectionConfigClass.getFullyQualifiedName(), new Section(sectionConfigClass));
    }

    for (Section section : sections.values()) {
      section.parseProperties();
    }
  }

  private void generate() throws IOException {

    try (BufferedWriter writer = Files.newBufferedWriter(outputFile, StandardCharsets.UTF_8)) {
      writer.write(header);

      for (Section section : sections.values()) {

        writer.write("## " + section.name + "\n\n");
        if (section.description != null && !section.description.isEmpty()) {
          writer.write(section.description);
        }

        for (Property property : section.properties) {
          writer.write("### `" + property.name + "`\n\n");
          writer.write(property.description);
        }
      }
    }
  }

  @SuppressWarnings("UnnecessaryUnicodeEscape")
  private String sanitizeDescription(Section section, String text) {

    Matcher matcher = EXTERNAL_LINK_PATTERN.matcher(text);
    StringBuilder sb = new StringBuilder();
    while (matcher.find()) {
      String url = matcher.group(1);
      String linkText = matcher.group(2);
      matcher.appendReplacement(sb, "[" + linkText + "](" + url + ")");
    }
    matcher.appendTail(sb);
    text = sb.toString();

    matcher = CODE_PATTERN.matcher(text);
    sb = new StringBuilder();
    while (matcher.find()) {
      String codeBlock = matcher.group(1);
      matcher.appendReplacement(sb, "`" + codeBlock + "`");
    }
    matcher.appendTail(sb);
    text = sb.toString();

    matcher = REF_PATTERN.matcher(text);
    sb = new StringBuilder();
    while (matcher.find()) {
      String fieldRef = matcher.group(1);
      String refText = matcher.group(2);
      String resolvedReference = resolveReference(section, fieldRef, refText);
      matcher.appendReplacement(sb, resolvedReference);
    }
    matcher.appendTail(sb);
    text = sb.toString();

    text = cleanupHtmlTags(text);

    // Clean up extra whitespace and normalize line breaks
    text = text.replaceAll("\\r\\n", "\n");
    text = text.replaceAll("\\r", "\n");
    text = text.replaceAll("\n(?![\n\\-])", " ");
    text = text.replaceAll(" {2,}", " ");
    text = text.replaceAll("\n ", "\n");
    text = text.replaceAll("\n{3,}", "\n\n");
    text = text.replaceAll("\u2424", "\n");
    text = text.trim() + "\n\n";

    return text;
  }

  private String resolveReference(Section section, String ref, String text) {
    String refTarget = KNOWN_REFS.get(ref);
    if (refTarget == null) {
      if (ref.equals("OAuth2Config#PREFIX")) {
        refTarget = rootPrefix;
      } else if (ref.startsWith("#")) {
        // local ref
        String fieldName = ref.substring(1);
        refTarget = section.refs.get(fieldName);
      } else if (section != null) {
        // external ref
        String[] parts = ref.split("#");
        String className = section.configClass.getPackageName() + "." + parts[0];
        String fieldName = parts[1];
        JavaClass classRef = builder.getClassByName(className);
        Section refSection = sections.get(classRef.getFullyQualifiedName());
        refTarget = refSection.refs.get(fieldName);
      }
    }
    if (text == null) {
      return "`" + refTarget + "`";
    }
    text = text.trim();
    return text.isEmpty() || text.equals(refTarget)
        ? "`" + refTarget + "`"
        : text + " (`" + refTarget + "`)";
  }

  @SuppressWarnings("UnnecessaryUnicodeEscape")
  private static String cleanupHtmlTags(String text) {
    // Convert HTML lists
    text = text.replaceAll("<ul> *", "");
    text = text.replaceAll(" *</ul>", "");
    text = text.replaceAll(" *<li> *", "- ");
    // Convert HTML paragraphs
    text = text.replaceAll("<p>\\s*", "\n");

    // Temporarily replace newlines in code blocks with a different character
    // to preserve them during the next steps. Here we use 'SYMBOL FOR NEWLINE' (U+2424).
    Matcher matcher = PRE_PATTERN.matcher(text);
    StringBuilder sb = new StringBuilder();
    while (matcher.find()) {
      String codeBlock = matcher.group(1).trim();
      codeBlock = codeBlock.replaceAll("[\r\n]", "\u2424");
      matcher.appendReplacement(sb, "\n\n```\u2424" + codeBlock + "\u2424```\n\n");
    }
    matcher.appendTail(sb);
    text = sb.toString();

    return text;
  }

  private class Section {

    private final JavaClass configClass;
    private final String prefix;
    private final String name;
    private final String description;
    private final Map<String, String> refs = new LinkedHashMap<>();
    private final List<Property> properties = new ArrayList<>();

    private Section(JavaClass configClass) {
      this.configClass = configClass;
      this.name = sanitizeSectionName(configClass.getSimpleName());
      this.prefix = resolvePrefix();
      parseLocalReferences();
      this.description = sanitizeDescription(this, configClass.getComment());
    }

    private String sanitizeSectionName(String className) {
      return className.replace("Config", "").replaceAll("([A-Z])", " $1").trim() + " Settings";
    }

    private String resolvePrefix() {
      JavaField groupNameField = configClass.getFieldByName("GROUP_NAME");
      if (groupNameField == null) {
        // Basic config: shares the root prefix
        return rootPrefix;
      } else {
        return rootPrefix + groupNameField.getInitializationExpression().replace("\"", "") + '.';
      }
    }

    private void parseLocalReferences() {
      for (JavaField field : configClass.getFields()) {
        String refName = field.getName();
        String refText = field.getInitializationExpression().replace("\"", "");
        if (refName.equals("PREFIX")) {
          refs.put("PREFIX", prefix);
        } else if (refName.equals("GROUP_NAME") || refName.startsWith("DEFAULT_")) {
          refs.put(refName, refText);
        } else {
          refs.put(refName, prefix + refText);
        }
      }
    }

    private void parseProperties() {
      for (JavaMethod method : configClass.getMethods()) {
        if (method.getComment() == null || !method.getTagsByName("hidden").isEmpty()) {
          continue;
        }
        method.getAnnotations().stream()
            .filter(a -> a.getType().getSimpleName().equals("io.smallrye.config.WithName"))
            .map(a -> a.getNamedParameter("value").toString())
            .findFirst()
            .ifPresent(
                name -> {
                  String propertyName = refs.get(name);
                  String description = sanitizeDescription(this, method.getComment());
                  properties.add(new Property(propertyName, description));
                });
      }
    }
  }

  private static class Property {

    private final String name;
    private final String description;
    private final boolean prefix;

    private Property(String name, String description) {
      prefix = description.contains("This is a prefix property");
      this.name = name + (prefix ? ".*" : "");
      this.description = description;
    }
  }
}
