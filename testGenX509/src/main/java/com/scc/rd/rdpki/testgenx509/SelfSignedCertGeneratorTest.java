/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.scc.rd.rdpki.testgenx509;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 *
 * @author terex
 */
public class SelfSignedCertGeneratorTest {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, CertIOException, IOException, NoSuchProviderException {
        // TODO code application logic here
        
        Security.addProvider(new BouncyCastleProvider());
        
        String cn = "CN= Chayanin,C= TH,SERIALNUMBER= 102496,E= terex@summit.com,L= SILOM,O= SUMMIT COMPUTER,OU= SECURITY INFRASTRUCTURE SECURITY MANAGEMENT,ST= BANGKOK";
        String signaturealgorithm = "SHA256withRSA";
        int day = 30;
        
        ArrayList<String> keyusage = new ArrayList<>();
        ArrayList<String[]> sanlist = new ArrayList<>();
        ArrayList<String[]> smimelist = new ArrayList<>();

        keyusage.add("DIGITAL_SIGNATURE");
        keyusage.add("NON_REPUDIATION");
        keyusage.add("KEY_ENCIPHERMENT");
        keyusage.add("DATA_ENCIPHERMENT");
        keyusage.add("KEY_AGREEMENT");
        keyusage.add("KEY_CERTSIGN");
        keyusage.add("CRL_SIGN");
        keyusage.add("ENCIPHER_ONLY");
        keyusage.add("DECIPHER_ONLY");
        
        sanlist.add(new String[]{"rfc822name", "rfc822name@pki.dev"});
        sanlist.add(new String[]{"dnsname", "*@pki.dev"});
        sanlist.add(new String[]{"ipaddress", "127.0.0.1"});
        sanlist.add(new String[]{"othername", "1.3.6.1.4.1.311.20.2.3", "terex@pki.dev"});


        smimelist.add(new String[]{"1.3.14.3.2.7", "56"});
        smimelist.add(new String[]{"1.2.840.113549.3.2", "128"});
        smimelist.add(new String[]{"1.2.840.113549.3.4", "2048"});
        smimelist.add(new String[]{"1.2.840.113549.1.5.11"});
        
        
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA","BC");
        keyPairGenerator.initialize(1024);
        //keyPairGenerator.initialize(2048);
        //keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        SelfSignedCertGenerator selfsign = SelfSignedCertGenerator.getInstant();
        X509Certificate cert = selfsign.generate(keyPair, signaturealgorithm, cn, day,keyusage,sanlist,smimelist);


        FileUtils.writeByteArrayToFile(new File("C:\\Users\\terex\\Desktop\\xx\\"+System.nanoTime()+".cer"), cert.getEncoded());
      
        
        
        
    }
    
}
