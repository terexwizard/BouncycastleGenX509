/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.scc.rd.rdpki.testgenx509;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 *
 * @author terex
 */
public class TestX509V3CertificateGenerator {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException, IllegalStateException, SignatureException, InvalidKeyException, IOException, OperatorCreationException, CertificateException {
        
        Security.addProvider(new BouncyCastleProvider());
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(1024, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
  
        // build a certificate generator
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        
        
        X500NameBuilder issuerBuilder = new X500NameBuilder();
        issuerBuilder.addRDN(BCStyle.CN, "terex");
        
        
        X500NameBuilder subjectBuilder = new X500NameBuilder();
        subjectBuilder.addRDN(BCStyle.CN, "name");
        subjectBuilder.addRDN(BCStyle.C, "TH");
        subjectBuilder.addRDN(BCStyle.SERIALNUMBER, "102496");
        subjectBuilder.addRDN(BCStyle.EmailAddress, "terex@dev.com");
        subjectBuilder.addRDN(BCStyle.L, "SILOM");
        subjectBuilder.addRDN(BCStyle.O, "SUMMIT COMPUTER");
        subjectBuilder.addRDN(BCStyle.OU, "SECURITY INFRASTRUCTURE SECURITY MANAGEMENT");
        subjectBuilder.addRDN(BCStyle.ST, "BANGKOK");
//        subjectBuilder.addRDN(BCStyle.E, "EEEE");
        
        Calendar calendar = Calendar.getInstance(Locale.ENGLISH);
        Date notbefore = calendar.getTime();
        // in 2 years
        calendar.add(Calendar.YEAR, 2);
        Date notafter = calendar.getTime();
        
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuerBuilder.build(), 
                BigInteger.valueOf(System.currentTimeMillis()),
                notbefore, notafter, 
                subjectBuilder.build(), keyPair.getPublic());
        X509Certificate cert = new JcaX509CertificateConverter()
          .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
        
        
        FileUtils.writeByteArrayToFile(new File("C:\\Users\\terex\\Desktop\\xx\\"+System.nanoTime()+".cer"), cert.getEncoded());
        
        
    }
    
}
