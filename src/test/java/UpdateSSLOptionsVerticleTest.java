
import io.vertx.core.AbstractVerticle;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.JksOptions;
import io.vertx.core.net.SSLOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.testng.Assert;
import org.testng.annotations.Test;

public class UpdateSSLOptionsVerticleTest {

    private static final String HOST = "localhost";
    private static final int PORT = 8443;

    private static final Path INITIAL_KEYSTORE = Path.of("initial-keystore.p12");
    private static final Path NEW_KEYSTORE = Path.of("new-keystore.p12");

    private static final String PASSWORD = "test-password";

    private static final List<MyVerticle> myVerticles = new ArrayList<>();

    public static class MyVerticle extends AbstractVerticle {

        private static final AtomicLong ID = new AtomicLong(0);

        private long id = 0;
        private HttpServer server;

        @Override
        public void start(Promise<Void> startPromise) throws Exception {

            HttpServerOptions options = new HttpServerOptions()
                    .setSsl(true)
                    .setKeyStoreOptions(new JksOptions().setPath(INITIAL_KEYSTORE.toString()).setPassword(PASSWORD));

            Router router = Router.router(this.vertx);
            router.route().handler(this::handleRequest);

            this.id = ID.addAndGet(1);

            this.vertx.createHttpServer(options)
                    .requestHandler(router)
                    .listen(PORT, HOST, handler -> {
                        if (handler.succeeded()) {
                            server = handler.result();
                            myVerticles.add(this);
                            startPromise.complete();
                        } else {
                            startPromise.fail(handler.cause());
                        }
                    });
        }

        public void handleRequest(RoutingContext ctx) {
            ctx.response().setStatusCode(200).end(Long.toString(this.id));
        }

    }

    @Test
    public void test() throws Exception {

        DeploymentOptions deploymentOptions = new DeploymentOptions().setInstances(2);

        // Generate self signed certifices and place them in a keystore
        generateKeystore(INITIAL_KEYSTORE, PASSWORD);
        generateKeystore(NEW_KEYSTORE, PASSWORD);

        Vertx vertx = Vertx.vertx();
        vertx.deployVerticle(MyVerticle.class.getName(), deploymentOptions).toCompletionStage().toCompletableFuture().join();

        WebClientOptions webClientOptions = new WebClientOptions()
                .setSsl(true)
                .setKeepAlive(false)
                .setDefaultHost(HOST)
                .setDefaultPort(PORT)
                .setTrustStoreOptions(new JksOptions().setPath(INITIAL_KEYSTORE.toString()).setPassword(PASSWORD));

        WebClient webClient = WebClient.create(vertx, webClientOptions);

        // Send one request to show that everything is working as expected
        HttpResponse<Buffer> response = webClient.get("").send().toCompletionStage().toCompletableFuture().join();
        Assert.assertEquals(response.statusCode(), 200);
        System.out.println("Initial verticle ID: " + response.bodyAsString());
        System.out.println();

        webClient.close();

        // Now update certificates
        JksOptions newJksOptions = new JksOptions().setPath(NEW_KEYSTORE.toString()).setPassword(PASSWORD);

        for (MyVerticle verticle : myVerticles) {
            System.out.println("Updating SSL Options for verticle " + verticle.id);
            SSLOptions newOptions = new SSLOptions().setKeyCertOptions(newJksOptions);
            verticle.server.updateSSLOptions(newOptions).toCompletionStage().toCompletableFuture().join();
        }
        System.out.println();

        // Recreate web client with new certificates
        webClientOptions.setTrustStoreOptions(newJksOptions);
        webClient = WebClient.create(vertx, webClientOptions);

        // Should always work but fails
        for (int i = 0; i < 4; i++) {
            System.out.println("Iteration " + i);

            response = webClient.get("").send().toCompletionStage().toCompletableFuture().join();
            Assert.assertEquals(response.statusCode(), 200);
            System.out.println("Verticle ID: " + response.bodyAsString());
            System.out.println();
        }

    }

    private static void generateKeystore(Path path, String password) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Setup
        SecureRandom secureRandom = new SecureRandom();
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(2, ChronoUnit.DAYS));
        Date notAfter = Date.from(now.plus(2, ChronoUnit.DAYS));

        AlgorithmIdentifier sha1 = new DefaultDigestAlgorithmIdentifierFinder().find("SHA1");
        AlgorithmIdentifier sha256WithRSA = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
        AlgorithmIdentifier digestAlg = new DefaultDigestAlgorithmIdentifierFinder().find(sha256WithRSA);

        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");

        BcRSAContentSignerBuilder contentSigner = new BcRSAContentSignerBuilder(sha256WithRSA, digestAlg);
        DigestCalculator digestCalculator = new BcDigestCalculatorProvider().get(sha1);

        X509ExtensionUtils extensions = new X509ExtensionUtils(digestCalculator);

        RSAKeyPairGenerator rsaGenerator = new RSAKeyPairGenerator();
        rsaGenerator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), secureRandom, 2048, 100));

        // Create Root Certificate
        AsymmetricCipherKeyPair rootCertKeyPair = rsaGenerator.generateKeyPair();
        BigInteger rootCertSerialNumber = BigInteger.valueOf(Math.abs(secureRandom.nextLong()));

        X500Name rootCertIssuer = new X500NameBuilder().addRDN(BCStyle.CN, "root").build();
        X500Name rootCertSubject = rootCertIssuer;

        ContentSigner rootCertSigner = contentSigner.build(rootCertKeyPair.getPrivate());
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(rootCertKeyPair.getPublic());

        X509v3CertificateBuilder rootCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, rootCertSerialNumber, notBefore, notAfter, rootCertSubject, subjectPublicKeyInfo);

        // http://certificateerror.blogspot.com/2011/02/how-to-validate-subject-key-identifier.html
        rootCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, extensions.createAuthorityKeyIdentifier(subjectPublicKeyInfo));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, extensions.createSubjectKeyIdentifier(subjectPublicKeyInfo));

        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        X509CertificateHolder caCertificateHolder = rootCertBuilder.build(rootCertSigner);

        X509Certificate rootCert = certConverter.getCertificate(caCertificateHolder);

        // Create Issued Cert
        AsymmetricCipherKeyPair issuedCertKeyPair = rsaGenerator.generateKeyPair();
        PublicKey issuedCertPublicKey = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(issuedCertKeyPair.getPublic()));
        PrivateKey issuedCertPrivateKey = BouncyCastleProvider.getPrivateKey(PrivateKeyInfoFactory.createPrivateKeyInfo(issuedCertKeyPair.getPrivate()));

        X500Name issuedCertSubject = new X500NameBuilder().addRDN(BCStyle.CN, "localhost").build();

        BigInteger issuedCertSerialNumber = BigInteger.valueOf(Math.abs(secureRandom.nextLong()));

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertPublicKey);
        PKCS10CertificationRequest csr = p10Builder.build(rootCertSigner);

        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, issuedCertSerialNumber, notBefore, notAfter, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[]{
            new GeneralName(GeneralName.dNSName, "localhost"),
            new GeneralName(GeneralName.dNSName, "localhost.localdomain"),
            new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
            new GeneralName(GeneralName.iPAddress, "0:0:0:0:0:0:0:1")
        }));

        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(rootCertSigner);

        X509Certificate issuedCert = certConverter.getCertificate(issuedCertHolder);

        issuedCert.verify(BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(rootCertKeyPair.getPublic())), "BC");

        Certificate[] certChain = {issuedCert, rootCert};

        KeyStore keystore = KeyStore.getInstance("PKCS12");

        keystore.load(null, password.toCharArray());
        keystore.setCertificateEntry("ca", rootCert);

        keystore.setKeyEntry("localhost", issuedCertPrivateKey, password.toCharArray(), certChain);

        try (OutputStream outputStream = Files.newOutputStream(path)) {
            keystore.store(outputStream, password.toCharArray());
            outputStream.flush();
        }

    }

}
