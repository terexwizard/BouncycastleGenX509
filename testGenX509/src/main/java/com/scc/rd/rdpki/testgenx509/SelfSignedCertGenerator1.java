package com.scc.rd.rdpki.testgenx509;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Utility class for generating self-signed certificates.
 *
 * @author Mister PKI
 */
public class SelfSignedCertGenerator1 {
    
    private SelfSignedCertGenerator1() {}
    
    
    public static SelfSignedCertGenerator1 getInstant() {
        return new SelfSignedCertGenerator1();
    }

    /**
     * Generates a self signed certificate using the BouncyCastle lib.
     *
     * @param keyPair used for signing the certificate with PrivateKey
     * @param hashAlgorithm Hash function
     * @param cn Common Name to be used in the subject dn
     * @param days validity period in days of the certificate
     * @param keyusage
     * @param sanlist
     * @param smimelist
     *
     * @return self-signed X509Certificate
     *
     * @throws OperatorCreationException on creating a key id
     * @throws CertIOException on building JcaContentSignerBuilder
     * @throws CertificateException on getting certificate from provider
     */
    public  X509Certificate generate( KeyPair keyPair,
                                        String hashAlgorithm,
                                        String cn,
                                        int days,
                                        ArrayList<String> keyusage,
                                        ArrayList<String[]> sanlist,
                                        ArrayList<String[]> smimelist)
        throws OperatorCreationException, CertificateException, CertIOException, IOException{

        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(Duration.ofDays(days)));

        ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm).build(keyPair.getPrivate());
        X500Name x500Name = new X500Name(cn);
        
        X500NameBuilder issuerBuilder = new X500NameBuilder();
        issuerBuilder.addRDN(BCStyle.CN, "terex");

        X509v3CertificateBuilder certificateBuilder =
          //new JcaX509v3CertificateBuilder(x500Name,
           new JcaX509v3CertificateBuilder(issuerBuilder.build(),
            BigInteger.valueOf(now.toEpochMilli()),
            notBefore,
            notAfter,
            x500Name,
            keyPair.getPublic())
            .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
            .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(keyPair.getPublic()))
            .addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        this.addKeyUsage(certificateBuilder, keyusage);
        this.addSan(certificateBuilder, sanlist);
        this.addEnhancedKeyUsage(certificateBuilder);
        this.addSMIME(certificateBuilder, smimelist);
        

        return new JcaX509CertificateConverter()
          .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
        
    }
    
    
    private void addKeyUsage(X509v3CertificateBuilder certificateBuilder,ArrayList<String> keyusage) throws CertIOException, IOException{
        
        int usage = 0;
        for(String key : keyusage){
            if(key.toLowerCase().replace("_", "").equals("digitalSignature".toLowerCase())){
                usage += KeyUsage.digitalSignature;
            }else if(key.toLowerCase().replace("_", "").equals("nonRepudiation".toLowerCase())){
                usage += KeyUsage.nonRepudiation;
            }else if(key.toLowerCase().replace("_", "").equals("keyEncipherment".toLowerCase())){
                usage += KeyUsage.keyEncipherment;
            }else if(key.toLowerCase().replace("_", "").equals("dataEncipherment".toLowerCase())){
                usage += KeyUsage.dataEncipherment;
            }else if(key.toLowerCase().replace("_", "").equals("keyAgreement".toLowerCase())){
                usage += KeyUsage.keyAgreement;
            }else if(key.toLowerCase().replace("_", "").equals("keyCertSign".toLowerCase())){
                usage += KeyUsage.keyCertSign;
            }else if(key.toLowerCase().replace("_", "").equals("cRLSign".toLowerCase())){
                usage += KeyUsage.cRLSign;
            }else if(key.toLowerCase().replace("_", "").equals("encipherOnly".toLowerCase())){
                usage += KeyUsage.encipherOnly;
            }else if(key.toLowerCase().replace("_", "").equals("decipherOnly".toLowerCase())){
                usage += KeyUsage.decipherOnly;
            }
        }
        
        certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
        
    }
    
    private void addSan(X509v3CertificateBuilder certificateBuilder,ArrayList<String[]> sanlist) throws CertIOException, IOException{
        
        ArrayList<GeneralName> altNames = new ArrayList<>();

        for(String[] san : sanlist){
            if(san[0].toLowerCase().equals("rfc822name")){

                GeneralName generalnames = new GeneralName(GeneralName.rfc822Name, san[1]);
                altNames.add(generalnames);
                
            }else if(san[0].toLowerCase().equals("dnsname")){
                
                GeneralName generalnames = new GeneralName(GeneralName.dNSName, san[1]);
                altNames.add(generalnames);
                
            }else if(san[0].toLowerCase().equals("directoryname")){

                if(!san[1].equals("")){
                    
                    GeneralName generalnames = new GeneralName(GeneralName.directoryName, san[1]);
                    altNames.add(generalnames);
                }

            }else if(san[0].toLowerCase().equals("x400address")){

                if(!san[1].equals("")){
                    
                    GeneralName generalnames = new GeneralName(GeneralName.x400Address, san[1]);
                    altNames.add(generalnames);
                }

            }else if(san[0].toLowerCase().equals("edipartyname")){
                  
                GeneralName generalnames = new GeneralName(GeneralName.ediPartyName, san[1]);
                altNames.add(generalnames);
            }else if(san[0].toLowerCase().equals("uriname")||
                     san[0].toLowerCase().equals("uniformresourceidentifier")){

                GeneralName generalnames = new GeneralName(GeneralName.uniformResourceIdentifier, san[1]);
                altNames.add(generalnames);

            }else if(san[0].toLowerCase().equals("ipaddressname") ||
                     san[0].toLowerCase().equals("ipaddress")){
                
               GeneralName generalnames = new GeneralName(GeneralName.iPAddress, san[1]);
                altNames.add(generalnames);
                
            }else if(san[0].toLowerCase().equals("oidname")||
                     san[0].toLowerCase().equals("registeredid")){

                GeneralName generalnames = new GeneralName(GeneralName.registeredID, san[1]);
                altNames.add(generalnames);
                
            }else if(san[0].toLowerCase().equals("othername")){

                if(san.length>2){

                    ASN1EncodableVector otherName = new ASN1EncodableVector(); 
//                    otherName.add(new DERObjectIdentifier(san[1]));
                    otherName.add(new ASN1ObjectIdentifier(san[1]));
                    otherName.add(new DERTaggedObject(true, 0, new DERUTF8String(san[2]))); 
                    
                    GeneralName generalnames = new GeneralName(GeneralName.otherName, new DERSequence(otherName));
                    altNames.add(generalnames);

                }
            }
        }
        
//        certificateBuilder.addExtension(MiscObjectIdentifiers.netscapeCertType, false,
//            new NetscapeCertType(NetscapeCertType.sslClient | NetscapeCertType.smime));
        
        
        GeneralNames subjectAltNames = new GeneralNames(altNames.toArray(new GeneralName[]{}));
        certificateBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        
        
    }
    
    private void addSMIME(X509v3CertificateBuilder certificateBuilder,ArrayList<String[]> smimelist) throws CertIOException, OperatorCreationException, CertificateEncodingException, IOException{
        
        SMIMECapabilityVector caps = new SMIMECapabilityVector();
        for(String[] smime : smimelist){
            if(smime.length == 1){
                caps.addCapability(new ASN1ObjectIdentifier(smime[0]));
            }else{
                caps.addCapability(new ASN1ObjectIdentifier(smime[0]), Integer.parseInt(smime[1]));
            }
        }
        
        certificateBuilder.addExtension(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities.getId()),
                false,new DERSequence(caps.toASN1EncodableVector()));
        
        
        //PKCSObjectIdentifiers.RC2_CBC
                
//        SMIMECapabilityVector caps = new SMIMECapabilityVector();
//        caps.addCapability(SMIMECapability.rC2_CBC, 128);
//        caps.addCapability(SMIMECapability.dES_CBC);
//        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
//        
//        
//        certificateBuilder.addExtension(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities.getId()),
//                false,new DERSequence(caps.toASN1EncodableVector()));
         
    }
    
    private void addEnhancedKeyUsage(X509v3CertificateBuilder certificateBuilder) throws CertIOException, OperatorCreationException, CertificateEncodingException{
        
        ArrayList<KeyPurposeId> EnhancedKey = new ArrayList<>();
        EnhancedKey.add(KeyPurposeId.id_kp_serverAuth);
        EnhancedKey.add(KeyPurposeId.id_kp_clientAuth);
        EnhancedKey.add(KeyPurposeId.id_kp_codeSigning);
        EnhancedKey.add(KeyPurposeId.id_kp_emailProtection);
        EnhancedKey.add(KeyPurposeId.id_kp_OCSPSigning);
        EnhancedKey.add(KeyPurposeId.anyExtendedKeyUsage);
        EnhancedKey.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.80.1")));
        
        certificateBuilder.addExtension(Extension.extendedKeyUsage, false, 
                new ExtendedKeyUsage(EnhancedKey.toArray(new KeyPurposeId[]{})));

    }

    /**
     * Creates the hash value of the public key.
     *
     * @param publicKey of the certificate
     *
     * @return SubjectKeyIdentifier hash
     *
     * @throws OperatorCreationException
     */
    private  SubjectKeyIdentifier createSubjectKeyId(final PublicKey publicKey) throws OperatorCreationException {
       SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
       DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

      return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
    }

    /**
     * Creates the hash value of the authority public key.
     *
     * @param publicKey of the authority certificate
     *
     * @return AuthorityKeyIdentifier hash
     *
     * @throws OperatorCreationException
     */
    private  AuthorityKeyIdentifier createAuthorityKeyId(final PublicKey publicKey)
      throws OperatorCreationException
    {
       SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
       DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

      return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
    }

  
}