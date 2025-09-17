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
package com.dremio.iceberg.authmgr.oauth2.test.kafka;

import static org.assertj.core.api.Assertions.assertThat;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Manager;
import com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer;
import com.dremio.iceberg.authmgr.oauth2.test.container.PolarisContainer;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.CatalogUtil;
import org.apache.iceberg.DataFile;
import org.apache.iceberg.Table;
import org.apache.iceberg.catalog.Namespace;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.rest.RESTCatalog;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.assertj.core.api.Condition;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.kafka.ConfluentKafkaContainer;
import org.testcontainers.lifecycle.Startables;
import org.testcontainers.shaded.org.awaitility.Awaitility;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class KafkaKeycloakIT {

  private static final String WAREHOUSE = "warehouse1";
  private static final String SCOPE = "catalog";
  private static final String CLIENT_ID = "Client1";
  private static final String CLIENT_SECRET = "s3cr3t";

  private static final String AWS_REGION = "us-west-2";
  private static final String AWS_ACCESS_KEY = "fake";
  private static final String AWS_SECRET_KEY = "fake";

  private static final String CONNECTOR_NAME = "test_connector-" + UUID.randomUUID();
  private static final String TEST_TOPIC = "test-topic-" + UUID.randomUUID();

  private static final int TEST_TOPIC_PARTITIONS = 2;

  private static final String TEST_DB = "db1";
  private static final String TEST_TABLE = "test1";

  private static final Logger KAFKA_LOGGER =
      LoggerFactory.getLogger("com.dremio.iceberg.authmgr.oauth2.test.container.KafkaContainer");
  private static final Logger CONNECT_LOGGER =
      LoggerFactory.getLogger("com.dremio.iceberg.authmgr.oauth2.test.container.ConnectContainer");

  private final Network network = Network.newNetwork();

  private final S3MockContainer s3 = createS3Container();
  private final KeycloakContainer keycloak = createKeycloakContainer();
  private final PolarisContainer polaris = createPolarisContainer();
  private final ConfluentKafkaContainer kafka = createKafkaContainer();
  private final GenericContainer<?> connect = createConnectContainer();

  private KafkaProducer<String, byte[]> kafkaProducer;

  private RESTCatalog icebergClient;
  private Admin kafkaClient;
  private KafkaConnectClient connectClient;

  @BeforeAll
  public void startContainers() {
    Startables.deepStart(s3, keycloak, polaris, kafka, connect).join();
    String token = keycloak.fetchNewToken(CLIENT_ID, CLIENT_SECRET, SCOPE);
    polaris.createCatalog(token, WAREHOUSE, "s3://test-bucket/path/to/data", "http://s3:9090");
  }

  @AfterAll
  @SuppressWarnings("EmptyTryBlock")
  public void stopContainers() {
    try (s3;
        keycloak;
        kafka;
        connect;
        polaris) {}
  }

  @BeforeEach
  public void startClients() throws Exception {
    kafkaProducer = initKafkaProducer();
    icebergClient = initIcebergClient();
    kafkaClient = initKafkaClient();
    connectClient = new KafkaConnectClient(connect.getMappedPort(8083));
    createTable();
    createTopic();
    startConnector();
  }

  @AfterEach
  @SuppressWarnings("EmptyTryBlock")
  public void stopClients() throws Exception {
    stopConnector();
    deleteTopic();
    dropTable();
    var connectClient = this.connectClient;
    var kafkaClient = this.kafkaClient;
    var icebergClient = this.icebergClient;
    var kafkaProducer = this.kafkaProducer;
    try (connectClient;
        kafkaClient;
        icebergClient;
        kafkaProducer) {}
  }

  @Test
  public void smokeTest() throws Exception {

    // Given
    // send two events, one in the current day, one in the past
    TestEvent event1 = new TestEvent(1, "type1", Instant.now(), "hello world!", "insert");
    Instant threeDaysAgo = Instant.now().minus(Duration.ofDays(3));
    TestEvent event2 = new TestEvent(2, "type2", threeDaysAgo, "having fun?", "insert");

    // When
    send(event1);
    send(event2);
    kafkaProducer.flush();

    // Then
    Table table =
        Awaitility.await()
            .atMost(Duration.ofSeconds(30))
            .pollInterval(Duration.ofSeconds(1))
            .until(
                () -> icebergClient.loadTable(TableIdentifier.of(TEST_DB, TEST_TABLE)),
                t -> t.snapshots().iterator().hasNext());

    List<DataFile> files = Lists.newArrayList(table.currentSnapshot().addedDataFiles(table.io()));
    assertThat(files).hasSize(2);
    assertThat(files.get(0).recordCount()).isEqualTo(1);
    assertThat(files.get(1).recordCount()).isEqualTo(1);

    Map<String, String> props = table.currentSnapshot().summary();
    assertThat(props)
        .hasKeySatisfying(
            new Condition<>() {
              @Override
              public boolean matches(String str) {
                return str.startsWith("kafka.connect.offsets.");
              }
            });
    assertThat(props).containsKey("kafka.connect.commit-id");
  }

  @SuppressWarnings("resource")
  private S3MockContainer createS3Container() {
    return new S3MockContainer("4.8.0")
        .withNetwork(network)
        .withNetworkAliases("s3")
        .withInitialBuckets("test-bucket");
  }

  @SuppressWarnings("resource")
  private KeycloakContainer createKeycloakContainer() {
    return new KeycloakContainer()
        .withNetwork(network)
        .withScope(SCOPE)
        .withClient(CLIENT_ID, CLIENT_SECRET, "client_secret_basic");
  }

  @SuppressWarnings("resource")
  private PolarisContainer createPolarisContainer() {
    return new PolarisContainer()
        .withNetwork(network)
        .withClient(CLIENT_ID, CLIENT_SECRET)
        .withEnv("AWS_REGION", AWS_REGION)
        .withEnv("polaris.features.\"SKIP_CREDENTIAL_SUBSCOPING_INDIRECTION\"", "true")
        .withEnv("quarkus.oidc.tenant-enabled", "true")
        .withEnv("quarkus.oidc.auth-server-url", "http://keycloak:8080/realms/master")
        // required because different iss claims will be used from inside and outside the network
        .withEnv("quarkus.oidc.token.issuer", "any")
        .withEnv("quarkus.oidc.client-id", CLIENT_ID)
        .withEnv("polaris.authentication.type", "external")
        .withEnv("polaris.oidc.principal-mapper.id-claim-path", "principal_id")
        .dependsOn(s3, keycloak);
  }

  @SuppressWarnings("resource")
  private ConfluentKafkaContainer createKafkaContainer() {
    String confluentVersion = System.getProperty("authmgr.test.cp.version");
    return new ConfluentKafkaContainer(
            DockerImageName.parse("confluentinc/cp-kafka:" + confluentVersion))
        .withNetwork(network)
        .withNetworkAliases("kafka")
        .withLogConsumer(new Slf4jLogConsumer(KAFKA_LOGGER));
  }

  @SuppressWarnings("resource")
  private GenericContainer<?> createConnectContainer() {
    String icebergConnectorVersion = System.getProperty("authmgr.test.iceberg-connector.version");
    String confluentVersion = System.getProperty("authmgr.test.cp.version");
    String standaloneJar = System.getProperty("authmgr.test.authmgr-standalone-jar");
    String command =
        "confluent-hub install --no-prompt iceberg/iceberg-kafka-connect:"
            + icebergConnectorVersion;
    ImageFromDockerfile image =
        new ImageFromDockerfile()
            .withDockerfileFromBuilder(
                builder ->
                    builder
                        .from("confluentinc/cp-kafka-connect:" + confluentVersion)
                        .run(command) // must be run as root
                        .build());
    return new GenericContainer<>(image)
        .withNetwork(network)
        .withNetworkAliases("connect")
        .withLogConsumer(new Slf4jLogConsumer(CONNECT_LOGGER))
        .withExposedPorts(8083)
        .withEnv("CONNECT_BOOTSTRAP_SERVERS", "kafka:9093")
        .withEnv("CONNECT_REST_ADVERTISED_HOST_NAME", "localhost")
        .withEnv("CONNECT_REST_PORT", "8083")
        .withEnv("CONNECT_GROUP_ID", "kc")
        .withEnv("CONNECT_CONFIG_STORAGE_TOPIC", "kc-config")
        .withEnv("CONNECT_CONFIG_STORAGE_REPLICATION_FACTOR", "1")
        .withEnv("CONNECT_OFFSET_STORAGE_TOPIC", "kc-offsets")
        .withEnv("CONNECT_OFFSET_STORAGE_REPLICATION_FACTOR", "1")
        .withEnv("CONNECT_STATUS_STORAGE_TOPIC", "kc-storage")
        .withEnv("CONNECT_STATUS_STORAGE_REPLICATION_FACTOR", "1")
        .withEnv("CONNECT_KEY_CONVERTER", "org.apache.kafka.connect.json.JsonConverter")
        .withEnv("CONNECT_KEY_CONVERTER_SCHEMAS_ENABLE", "false")
        .withEnv("CONNECT_VALUE_CONVERTER", "org.apache.kafka.connect.json.JsonConverter")
        .withEnv("CONNECT_VALUE_CONVERTER_SCHEMAS_ENABLE", "false")
        .withEnv("CONNECT_OFFSET_FLUSH_INTERVAL_MS", "500")
        .withEnv("CONNECT_PLUGIN_PATH", "/usr/share/confluent-hub-components")
        .withCopyFileToContainer(
            MountableFile.forHostPath(standaloneJar),
            "/usr/share/confluent-hub-components/iceberg-iceberg-kafka-connect/lib/")
        .waitingFor(
            new LogMessageWaitStrategy()
                .withRegEx(".*Finished starting connectors and tasks.*")
                .withTimes(1)
                .withStartupTimeout(Duration.ofMinutes(5)))
        .dependsOn(kafka);
  }

  private RESTCatalog initIcebergClient() {
    RESTCatalog restCatalog = new RESTCatalog();
    // URIs must be external to the network (i.e. localhost)
    restCatalog.initialize(
        WAREHOUSE,
        ImmutableMap.<String, String>builder()
            .put(CatalogProperties.URI, polaris.getCatalogApiEndpoint().toString())
            .put(CatalogProperties.FILE_IO_IMPL, "org.apache.iceberg.aws.s3.S3FileIO")
            .put("s3.endpoint", s3.getHttpEndpoint())
            .put("s3.path-style-access", "true")
            .put("s3.access-key-id", AWS_ACCESS_KEY)
            .put("s3.secret-access-key", AWS_SECRET_KEY)
            .put("client.region", AWS_REGION)
            .put("warehouse", WAREHOUSE)
            .put("header.Accept-Encoding", "none") // for debugging
            .put("rest.auth.type", OAuth2Manager.class.getName())
            .put("rest.auth.oauth2.client-id", CLIENT_ID)
            .put("rest.auth.oauth2.client-secret", CLIENT_SECRET)
            .put("rest.auth.oauth2.issuer-url", keycloak.getIssuerUrl().toString())
            .put("rest.auth.oauth2.scope", SCOPE)
            .put("rest.auth.oauth2.http.client-type", "apache")
            .build());
    return restCatalog;
  }

  private KafkaConnectClient.Config createConnectConfig() {
    return new KafkaConnectClient.Config(CONNECTOR_NAME)
        // connector properties
        .config("topics", TEST_TOPIC)
        .config("connector.class", "org.apache.iceberg.connect.IcebergSinkConnector")
        .config("tasks.max", 2)
        // set offset reset to the earliest, so we don't miss any test messages
        .config("consumer.override.auto.offset.reset", "earliest")
        .config("key.converter", "org.apache.kafka.connect.json.JsonConverter")
        .config("key.converter.schemas.enable", false)
        .config("value.converter", "org.apache.kafka.connect.json.JsonConverter")
        .config("value.converter.schemas.enable", true)
        .config("iceberg.control.commit.interval-ms", 1000)
        .config("iceberg.control.commit.timeout-ms", Integer.MAX_VALUE)
        .config("iceberg.kafka.auto.offset.reset", "earliest")
        .config("iceberg.tables", String.format("%s.%s", TEST_DB, TEST_TABLE))
        // catalog properties
        // (URIs must be internal to the network since communication is within the network)
        .config(
            "iceberg.catalog." + CatalogUtil.ICEBERG_CATALOG_TYPE,
            CatalogUtil.ICEBERG_CATALOG_TYPE_REST)
        .config("iceberg.catalog." + CatalogProperties.URI, "http://polaris:8181/api/catalog")
        .config(
            "iceberg.catalog." + CatalogProperties.FILE_IO_IMPL,
            "org.apache.iceberg.aws.s3.S3FileIO")
        .config("iceberg.catalog.s3.endpoint", "http://s3:9090")
        .config("iceberg.catalog.s3.access-key-id", AWS_ACCESS_KEY)
        .config("iceberg.catalog.s3.secret-access-key", AWS_SECRET_KEY)
        .config("iceberg.catalog.s3.path-style-access", true)
        .config("iceberg.catalog.client.region", AWS_REGION)
        .config("iceberg.catalog.warehouse", WAREHOUSE)
        .config("iceberg.catalog.rest.auth.type", OAuth2Manager.class.getName())
        .config("iceberg.catalog.rest.auth.oauth2.client-id", CLIENT_ID)
        .config("iceberg.catalog.rest.auth.oauth2.client-secret", CLIENT_SECRET)
        .config("iceberg.catalog.rest.auth.oauth2.issuer-url", "http://keycloak:8080/realms/master")
        .config("iceberg.catalog.rest.auth.oauth2.scope", SCOPE);
  }

  private KafkaProducer<String, byte[]> initKafkaProducer() {
    // URIs must be external to the network (i.e. localhost)
    return new KafkaProducer<>(
        Map.of(
            ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,
            kafka.getBootstrapServers(),
            ProducerConfig.CLIENT_ID_CONFIG,
            UUID.randomUUID().toString()),
        new StringSerializer(),
        new ByteArraySerializer());
  }

  private Admin initKafkaClient() {
    return AdminClient.create(
        Map.of(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, kafka.getBootstrapServers()));
  }

  private void createTable() {
    icebergClient.createNamespace(Namespace.of(TEST_DB));
    icebergClient.createTable(
        TableIdentifier.of(TEST_DB, TEST_TABLE), TestEvent.ICEBERG_SCHEMA, TestEvent.ICEBERG_SPEC);
  }

  private void dropTable() {
    icebergClient.dropTable(TableIdentifier.of(TEST_DB, TEST_TABLE));
    icebergClient.dropNamespace(Namespace.of(TEST_DB));
  }

  private void createTopic() throws ExecutionException, InterruptedException, TimeoutException {
    kafkaClient
        .createTopics(List.of(new NewTopic(TEST_TOPIC, TEST_TOPIC_PARTITIONS, (short) 1)))
        .all()
        .get(10, TimeUnit.SECONDS);
  }

  private void deleteTopic() throws ExecutionException, InterruptedException, TimeoutException {
    kafkaClient.deleteTopics(List.of(TEST_TOPIC)).all().get(10, TimeUnit.SECONDS);
  }

  private void startConnector() {
    KafkaConnectClient.Config config = createConnectConfig();
    connectClient.startConnector(config);
    connectClient.ensureConnectorRunning(config.getName());
  }

  private void stopConnector() {
    connectClient.stopConnector(CONNECTOR_NAME);
  }

  private void send(TestEvent event) throws ExecutionException, InterruptedException {
    byte[] bytes = event.serialize(TEST_TOPIC);
    kafkaProducer.send(new ProducerRecord<>(TEST_TOPIC, Long.toString(event.id()), bytes)).get();
  }
}
