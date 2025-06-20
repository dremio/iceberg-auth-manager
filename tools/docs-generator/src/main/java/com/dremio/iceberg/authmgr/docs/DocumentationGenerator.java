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
package com.dremio.iceberg.authmgr.docs;

import com.thoughtworks.qdox.JavaProjectBuilder;
import com.thoughtworks.qdox.model.JavaClass;
import com.thoughtworks.qdox.model.JavaField;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
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

  private static final Set<String> KNOWN_ENUMS =
      Set.of("GrantCommonNames", "Dialect", "JwtSigningAlgorithm", "ClientAuthentication");

  private final File inputFile;
  private final String className;
  private final String header;
  private final File outputFile;

  private String rootPrefix;
  private JavaClass topClass;

  public static void main(String[] args) throws IOException {
    String sourceFile = args[0];
    String className = args[1];
    String header = args[2];
    String outputFile = args[3];
    new DocumentationGenerator(new File(sourceFile), className, header, new File(outputFile))
        .generate();
  }

  public DocumentationGenerator(File inputFile, String className, String header, File outputFile) {
    this.inputFile = inputFile;
    this.className = className;
    this.header = header;
    this.outputFile = outputFile;
  }

  public void generate() throws IOException {

    Map<String, Map<String, String>> allProperties = parseProperties();

    try (FileWriter writer = new FileWriter(outputFile, StandardCharsets.UTF_8)) {
      writer.write(header);

      for (Map.Entry<String, Map<String, String>> entry : allProperties.entrySet()) {
        String sectionName = entry.getKey();
        Map<String, String> properties = entry.getValue();

        writer.write("## " + sectionName + "\n\n");

        for (Map.Entry<String, String> propertyEntry : properties.entrySet()) {
          String propertyName = propertyEntry.getKey();
          String propertyDescription = propertyEntry.getValue();
          writer.write("### `" + propertyName + "`\n\n");
          writer.write(propertyDescription);
        }
      }
    }
  }

  private Map<String, Map<String, String>> parseProperties() throws IOException {

    JavaProjectBuilder builder = new JavaProjectBuilder();
    builder.addSource(inputFile);
    topClass = builder.getClassByName(className);
    rootPrefix = topClass.getFieldByName("PREFIX").getInitializationExpression().replace("\"", "");

    Map<String, Map<String, String>> allProperties = new LinkedHashMap<>();

    for (JavaClass nestedClass : topClass.getNestedClasses()) {

      String prefix = resolvePrefix(nestedClass);

      Map<String, String> properties = new LinkedHashMap<>();
      allProperties.put(sanitizeSectionName(nestedClass.getSimpleName()), properties);

      for (JavaField field : nestedClass.getFields()) {
        if (field.getName().equals("PREFIX") || field.getName().startsWith("DEFAULT_")) {
          continue;
        }
        String propertyName = resolvePropertyName(field, prefix);
        String propertyDescription = sanitizePropertyDescription(nestedClass, field.getComment());
        properties.put(propertyName, propertyDescription);
      }
    }
    return allProperties;
  }

  private String sanitizeSectionName(String className) {
    return className.replaceAll("([A-Z])", " $1").trim() + " Settings";
  }

  private String resolvePrefix(JavaClass classRef) {
    if (classRef == topClass) {
      return "";
    }
    JavaField prefixField = classRef.getFieldByName("PREFIX");
    if (prefixField == null) {
      // Basic config: shares the root prefix
      return rootPrefix;
    } else {
      return rootPrefix
          + prefixField
              .getInitializationExpression()
              .replace("OAuth2Properties.PREFIX + ", "")
              .replace("\"", "");
    }
  }

  private String resolvePropertyName(JavaField field, String prefix) {
    return prefix
        + field.getInitializationExpression().replaceAll(".*PREFIX \\+ ", "").replace("\"", "");
  }

  private String sanitizePropertyDescription(JavaClass nestedClass, String text) {

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
      String resolvedReference = resolveReference(fieldRef, nestedClass, refText);
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

  private String resolveReference(String linkRef, JavaClass nestedClass, String text) {
    String className;
    String fieldName;
    if (linkRef.startsWith("#")) {
      className = nestedClass.getSimpleName();
      fieldName = linkRef.substring(1);
    } else {
      String[] parts = linkRef.split("#");
      className = parts[0];
      fieldName = parts[1];
    }
    String refTarget;
    if (KNOWN_ENUMS.contains(className)) {
      refTarget = fieldName.toLowerCase(Locale.ROOT);
    } else {
      JavaClass classRef =
          className.equals("OAuth2Properties")
              ? topClass
              : topClass.getNestedClassByName(className);
      JavaField field = classRef.getFieldByName(fieldName);
      if (fieldName.startsWith("DEFAULT_")) {
        refTarget = field.getInitializationExpression().replace("\"", "");
      } else {
        String prefix = resolvePrefix(classRef);
        refTarget = resolvePropertyName(field, prefix);
      }
    }
    return text != null ? text.trim() + " (`" + refTarget + "`)" : "`" + refTarget + "`";
  }

  private String cleanupHtmlTags(String text) {
    // Convert HTML lists
    text = text.replaceAll("<ul> *", "");
    text = text.replaceAll(" *</ul>", "");
    text = text.replaceAll(" *<li> *", "- ");
    // Convert HTML paragraphs
    text = text.replaceAll("<p>\\s*", "\n");

    // Temporarily replace newlines in code blocks with a different character
    // to preserve them during the next steps
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
}
