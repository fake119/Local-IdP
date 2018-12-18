package com.i2max.saml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import com.rackspace.saml.CertManager;

public class SAMLWrapper {
	private static final Logger logger = LoggerFactory.getLogger(SAMLWrapper.class);
	/*
## KeyStore Explorer 5.3.2 Download (http://keystore-explorer.org/downloads.html), RSA 2048로 만들고 서명알고리즘은 sha256RSA으로 생성되어야 함.

1. KeyStore에서 jks 파일 생성
2. RSA 인증서 생성(PKCS #12로 생성함, 2048 bit 선택, Name값은 대충 선택)
3. Export에서 Export Key Pair를 선택하여 .p12 파일로 내보내기 후 아래 명령어 실행

openssl pkcs12 -in local_idp.p12 -nokeys -out server.crt
openssl pkcs12 -in local_idp.p12 -out cert_and_private_key.pem -clcerts
openssl pkcs8 -topk8 -nocrypt -in cert_and_private_key.pem -out pkcs8_private_key.der -inform PEM -outform DER

 */
	public final static String RECIPIENT_URL = "https://ksisso-dev-ed.my.salesforce.com?so=00D90000000aNu7";
	
	private String loginEmail = null;
	private String publicKeyPath = "C:/certifications/local-idp/server.crt"; // crt is PEM(base64)
	private String privateKeyPath = "C:/certifications/local-idp/pkcs8_private_key.der"; // der is binary
	private String audienceUrl = "https://saml.salesforce.com";
	private String issuer = "http://local-idp.i2max.co.kr";
	
	static HashMap<String, List<String>> attributes = new HashMap<String, List<String>>();
	
	public SAMLWrapper(String loginEmail) {
		this.loginEmail = loginEmail;
	}
	
//	public static void main(String[] args) throws Throwable {
//		SAMLWrapper samlTest = new SAMLWrapper("fake200@korea.com");
//		Integer samlAssertionExpirationDays = 10;
//		
//		Response response = samlTest.createSAMLResponse(new DateTime(), attributes, samlAssertionExpirationDays);
//		
//		ResponseMarshaller marshaller = new ResponseMarshaller();
//		Element element = marshaller.marshall(response);
//		
//		System.out.println(XMLHelper.nodeToString(element));
//	}
	
	public String getSAML () throws MarshallingException {
		Integer samlAssertionExpirationDays = 10;
		
		Response response = createSAMLResponse(new DateTime(), attributes, samlAssertionExpirationDays);
		
		ResponseMarshaller marshaller = new ResponseMarshaller();
		Element element = marshaller.marshall(response);
		
		String strSAML = XMLHelper.nodeToString(element);
		logger.debug(strSAML);
		
		return strSAML;
	}
	
	static String readFile(String path, Charset encoding) throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return new String(encoded, encoding);
	}

	private Response createResponse(final DateTime issueDate, Issuer issuer, Status status, Assertion assertion) {
		ResponseBuilder responseBuilder = new ResponseBuilder();
		Response response = responseBuilder.buildObject();
		response.setID(UUID.randomUUID().toString());
		response.setIssueInstant(issueDate);
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssuer(issuer);
		response.setStatus(status);
		response.setDestination(RECIPIENT_URL);// https://ksisso-dev-ed.my.salesforce.com?so=00D90000000aNu7 하기 subjectConfirmationData.setRecipient(RECIPIENT_URL)에서 so parameter 없으면 error Destination에는 없어도 되는 듯.
//		response.setDestination("https://ksisso-dev-ed.my.salesforce.com");
		response.getAssertions().add(assertion);
		return response;
	}

	private Signature createSignature() throws Throwable {
		SignatureBuilder builder = new SignatureBuilder();
		Signature signature = builder.buildObject();

		CertManager certManager = new CertManager();

		Credential credential = certManager.getSigningCredential(publicKeyPath, privateKeyPath);
		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1); // 인증서가 RSA인지 DSA인지 일치 시켜야 함. openssl로 만들 때 정할 수 있음.
//		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_DSA);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		
		X509KeyInfoGeneratorFactory keyFactory = new X509KeyInfoGeneratorFactory();
		keyFactory.setEmitEntityCertificate(true);
		
		KeyInfoGenerator keyGenerator = keyFactory.newInstance();
		KeyInfo keyInfo = keyGenerator.generate(credential);

		if (keyInfo == null) {
			System.out.println("keyinfo is null.");
		}
		signature.setKeyInfo(keyInfo);
		
		return signature;
	}

	private Response createSAMLResponse(final DateTime authenticationTime, final HashMap<String, List<String>> attributes,
			Integer samlAssertionDays) {

		try {
			DefaultBootstrap.bootstrap();

			Signature signature = createSignature();
			Status status = createStatus();
			Issuer responseIssuer = null;
			Issuer assertionIssuer = null;
			Subject subject = null;
			AttributeStatement attributeStatement = null;

			responseIssuer = createIssuer(issuer);
			assertionIssuer = createIssuer(issuer);

			subject = createSubject(samlAssertionDays);

			if (attributes != null && attributes.size() != 0) {
				attributeStatement = createAttributeStatement(attributes);
			}

			AuthnStatement authnStatement = createAuthnStatement(authenticationTime);

			Assertion assertion = createAssertion(new DateTime(), subject, assertionIssuer, authnStatement, attributeStatement);

			Response response = createResponse(new DateTime(), responseIssuer, status, assertion);
			response.setSignature(signature);
			
			// for signature.
			ResponseMarshaller marshaller = new ResponseMarshaller();
			Element element = marshaller.marshall(response);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			XMLHelper.writeNode(element, baos);

			if (signature != null) {
				Signer.signObject(signature);
			}
			
			return response;

		} catch (Throwable t) {
			t.printStackTrace();
			return null;
		}
	}

	private Status createStatus() {
		StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
		StatusCode statusCode = statusCodeBuilder.buildObject();
		statusCode.setValue(StatusCode.SUCCESS_URI);

		StatusBuilder statusBuilder = new StatusBuilder();
		Status status = statusBuilder.buildObject();
		status.setStatusCode(statusCode);

		return status;
	}
	
	
	private Issuer createIssuer(final String issuerName) {
		// create Issuer object
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(issuerName);	
		return issuer;
	}
	
	private Subject createSubject(final Integer samlAssertionDays) {
		DateTime currentDate = new DateTime();
		if (samlAssertionDays != null)
			currentDate = currentDate.plusDays(samlAssertionDays);
		
		// create name element
		NameIDBuilder nameIdBuilder = new NameIDBuilder(); 
		NameID nameId = nameIdBuilder.buildObject();
		nameId.setValue(loginEmail);
		nameId.setFormat(NameIDType.UNSPECIFIED);
		
		SubjectConfirmationDataBuilder dataBuilder = new SubjectConfirmationDataBuilder();
		SubjectConfirmationData subjectConfirmationData = dataBuilder.buildObject();
		subjectConfirmationData.setRecipient(RECIPIENT_URL); // https://ksisso-dev-ed.my.salesforce.com?so=00D90000000aNu7 so parameter 없으면 error
//		subjectConfirmationData.setRecipient("https://ksisso-dev-ed.my.salesforce.com"); // so parameter 없으면 error
		subjectConfirmationData.setNotOnOrAfter(currentDate);
		
		SubjectConfirmationBuilder subjectConfirmationBuilder = new SubjectConfirmationBuilder();
		SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
		
		// create subject element
		SubjectBuilder subjectBuilder = new SubjectBuilder();
		Subject subject = subjectBuilder.buildObject();
		subject.setNameID(nameId);
		subject.getSubjectConfirmations().add(subjectConfirmation);
		
		return subject;
	}
	
	private AuthnStatement createAuthnStatement(final DateTime issueDate) {
		// create authcontextclassref object
		AuthnContextClassRefBuilder classRefBuilder = new AuthnContextClassRefBuilder();
		AuthnContextClassRef classRef = classRefBuilder.buildObject();
		classRef.setAuthnContextClassRef(AuthnContext.UNSPECIFIED_AUTHN_CTX);
		
		// create authcontext object
		AuthnContextBuilder authContextBuilder = new AuthnContextBuilder();
		AuthnContext authnContext = authContextBuilder.buildObject();
		authnContext.setAuthnContextClassRef(classRef);
		
		// create authenticationstatement object
		AuthnStatementBuilder authStatementBuilder = new AuthnStatementBuilder();
		AuthnStatement authnStatement = authStatementBuilder.buildObject();
		authnStatement.setAuthnInstant(issueDate);
		authnStatement.setAuthnContext(authnContext);
		
		return authnStatement;
	}
	
	private AttributeStatement createAttributeStatement(HashMap<String, List<String>> attributes) {
		// create authenticationstatement object
		AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
		AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
		
		AttributeBuilder attributeBuilder = new AttributeBuilder();
		if (attributes != null) {
			for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
				Attribute attribute = attributeBuilder.buildObject();
				attribute.setName(entry.getKey());
				
				for (String value : entry.getValue()) {
					XSStringBuilder stringBuilder = new XSStringBuilder();
					XSString attributeValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
					attributeValue.setValue(value);
					attribute.getAttributeValues().add(attributeValue);
				}
				
				attributeStatement.getAttributes().add(attribute);
			}
		}
		
		return attributeStatement;
	}

	private Assertion createAssertion(final DateTime issueDate, Subject subject, Issuer issuer, AuthnStatement authnStatement, AttributeStatement attributeStatement) {
		AssertionBuilder assertionBuilder = new AssertionBuilder();
		Assertion assertion = assertionBuilder.buildObject();
		assertion.setID(UUID.randomUUID().toString());
		assertion.setIssueInstant(issueDate);
		assertion.setSubject(subject);
		assertion.setIssuer(issuer);
		
		ConditionsBuilder conditionsBuilder = new ConditionsBuilder();
		Conditions conditions = conditionsBuilder.buildObject();
		conditions.setNotBefore(new DateTime());
		conditions.setNotOnOrAfter(new DateTime().plusMinutes(10));
		
		AudienceRestrictionBuilder audienceRestrictionBuilder = new AudienceRestrictionBuilder();
		AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
		
		AudienceBuilder audienceBuilder = new AudienceBuilder();
		Audience audience = audienceBuilder.buildObject();
		audience.setAudienceURI(audienceUrl);
		audienceRestriction.getAudiences().add(audience);
		conditions.getAudienceRestrictions().add(audienceRestriction);
		
		assertion.setConditions(conditions);
		
		if (authnStatement != null)
			assertion.getAuthnStatements().add(authnStatement);

		if (attributeStatement != null)
			assertion.getAttributeStatements().add(attributeStatement);

		return assertion;
	}
	
}
