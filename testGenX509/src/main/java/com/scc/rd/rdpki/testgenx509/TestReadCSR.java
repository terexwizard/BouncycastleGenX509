/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.scc.rd.rdpki.testgenx509;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.codehaus.jettison.json.JSONArray;

/**
 *
 * @author terex
 */
public class TestReadCSR {
    

    private static final String COUNTRY = "2.5.4.6";
    private static final String STATE = "2.5.4.8";
    private static final String LOCALE = "2.5.4.7";
    private static final String ORGANIZATION = "2.5.4.10";
    private static final String ORGANIZATION_UNIT = "2.5.4.11";
    private static final String COMMON_NAME = "2.5.4.3";
    private static final String EMAIL = "2.5.4.9";
    
    
    private static final String csrPEM = "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
"MIIEJzCCAw8CAQAwgcQxCzAJBgNVBAYTAlRIMRAwDgYDVQQIEwdCQU5HS09LMQ8wDQYDVQQFEwYx\n" +
"MDI0OTYxHzAdBgkqhkiG9w0BCQEMEHRlcmV4QHN1bW1pdC5jb20xNDAyBgNVBAsTK1NFQ1VSSVRZ\n" +
"IElORlJBU1RSVUNUVVJFIFNFQ1VSSVRZIE1BTkFHRU1FTlQxETAPBgNVBAMTCENoYXlhbmluMQ4w\n" +
"DAYDVQQHEwVTSUxPTTEYMBYGA1UEChMPU1VNTUlUIENPTVBVVEVSMIIBIjANBgkqhkiG9w0BAQEF\n" +
"AAOCAQ8AMIIBCgKCAQEAqMgLARQ1kTVhVkZF/bUQofkRURlGZak8kYh6YYvZFUoDvJexQTxFx9WZ\n" +
"XpaFkv/mA2Ly6xumUI94f8/oD95Aj3ndmA0Fo17ToqDLXbUsn3eYWX9a+DE8fcvHjDc1N1hDzMel\n" +
"1XM0i7GB69qGXKDdPv0KSg2ISmSA8mvofcZKilTygRYQDDrFZDSyIC+LtNy6V13M6UKJCUbjuhhY\n" +
"mofl5NRvfrOrOgzorYx9tWIDaL4Y32b1G3MMrOctcKJuzX4oVtns+rT76QyT+25kv43BbFywiUBd\n" +
"7UgUrPeRfx5pMMwtW+yQNM9R+GerJ/DqccQ3vwpxJOwrJQLQvWi9QbAS9QIDAQABoIIBGzCCARcG\n" +
"CSqGSIb3DQEJDjGCAQgwggEEMFwGCSqGSIb3DQEJDwRPME0wCgYFKw4DAgcCATgwDgYIKoZIhvcN\n" +
"AwICAgCAMA4GCCqGSIb3DQMEAgIIADAOBggqhkiG9w0DBwICAKgwDwYJYIZIAWUDBAEFAgIAgDAp\n" +
"BgNVHSUEIjAgBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcKAwwwSgYDVR0RBEMwQaAkBgor\n" +
"BgEEAYI3FAIDoBYMFHRlcmV4QHBraS5zdW1taXQuZGV2gRlyZmM4MjJuYW1lQHBraS5zdW1taXQu\n" +
"ZGV2MB0GA1UdDgQWBBTgDgwQlhwNJ7+aM6HA8sBeV7+73TAOBgNVHQ8BAf8EBAMCBeAwDQYJKoZI\n" +
"hvcNAQELBQADggEBAKBE+DhFFKS0kNKA2gXAAocmH01aJzwYJOcs5vMZhrlLBAIncxMwij/ykCpe\n" +
"kP2ap9PQvJ+GGE4pXeebYlfZb3B1+W7mLhcCrnBZujHnxoNVImdXltf2dKmomNG2jOsLTdNfklq4\n" +
"HTHoXnNnMz0KOS8FzpGfIqXEMa0xIhqLDIVrmjdqSBtZDzzrZVQnfnjuKLFm3gFaNeglAeQo1FtS\n" +
"5m1SpBK/Zd5RMgUVOkCuLKMQ1HRULdiCJsBFVR2WoqHb0a59CJIKnBnWUir4kPUOQ4DM9biFgg4Z\n" +
"mjs7XyuncsRf3yI+QfP4yZPrET7C/QUqV74lYf0YovkK4A4dN+L1N34=\n" +
"-----END NEW CERTIFICATE REQUEST-----";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        // TODO code application logic here
        
        InputStream stream = new ByteArrayInputStream(csrPEM.getBytes(StandardCharsets.UTF_8));

        TestReadCSR m = new TestReadCSR();
        m.readCertificateSigningRequest(stream);
    }
    
    
    public String readCertificateSigningRequest(InputStream csrStream) throws IOException, Exception {

        PKCS10CertificationRequest csr = convertPemToPKCS10CertificationRequest(csrStream);
        String compname = null;

        if (csr == null) {
            System.out.println("FAIL! conversion of Pem To PKCS10 Certification Request");
        } else {

           X500Name x500Name = csr.getSubject();
           System.out.println("x500Name is: " + x500Name + "\n");

//           RDN cn = x500Name.getRDNs(BCStyle.EmailAddress)[0];
//           System.out.println(cn.getFirst().getValue().toString());
//           System.out.println("BCStyle.EmailAddress:"+x500Name.getRDNs(BCStyle.EmailAddress)[0]);
//           
//           System.out.println("COUNTRY: " + getX500Field(COUNTRY, x500Name));
//           System.out.println("STATE: " + getX500Field(STATE, x500Name));
//           System.out.println("LOCALE: " + getX500Field(LOCALE, x500Name));
//           System.out.println("ORGANIZATION: " + getX500Field(ORGANIZATION, x500Name));
//           System.out.println("ORGANIZATION_UNIT: " + getX500Field(ORGANIZATION_UNIT, x500Name));
//           System.out.println("COMMON_NAME: " + getX500Field(COMMON_NAME, x500Name));
//           System.out.println("EMAIL: " + getX500Field(EMAIL, x500Name));

           System.out.println("COUNTRY2: " + getX500Field(BCStyle.C.getId(), x500Name));
           System.out.println("STATE2: " + getX500Field(BCStyle.ST.getId(), x500Name));
           System.out.println("LOCALE2: " + getX500Field(BCStyle.L.getId(), x500Name));
           System.out.println("ORGANIZATION2: " + getX500Field(BCStyle.O.getId(), x500Name));
           System.out.println("ORGANIZATION_UNIT2: " + getX500Field(BCStyle.OU.getId(), x500Name));
           System.out.println("COMMON_NAME2: " + getX500Field(BCStyle.CN.getId(), x500Name));
           System.out.println("EMAIL2: " + getX500Field(BCStyle.E.getId(), x500Name));

           
            getsubjectAlternativeName(csr);
            getSMIME(csr);
            //getKeyUsage(csr);//nowork
            
            
        }
        return compname;
    }
    
    
    
    private void getKeyUsage(PKCS10CertificationRequest csr) throws IOException{
        Attribute[] certAttributes = csr.getAttributes();
        for (Attribute attribute : certAttributes) {
            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {

                System.out.println(">>KeyUsage:"+attribute.getAttrValues().size());
                
                //key usage
                ASN1Encodable[] a = attribute.getAttrValues().toArray();
                for(ASN1Encodable a1 :a){
                    
                    System.out.println(">>key usage:"+a1.toASN1Primitive());
                    System.out.println(">>key usage:"+Hex.toHexString(a1.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
                    
                    
//                    ASN1Sequence otherName = (ASN1Sequence) a1.toASN1Primitive().getName();
//                    Iterator i = otherName.getObjects().asIterator();
//                    String oidoth = "";
//                    String valueoth = "";
//                    while(i.hasNext()){
//
//                        Object obj = i.next();
//                        if(obj instanceof ASN1ObjectIdentifier){
//                            ASN1ObjectIdentifier objiden = (ASN1ObjectIdentifier) obj;
////                                System.out.println(">>ASN1ObjectIdentifier:"+objiden.getId());
//
//                            oidoth = objiden.getId();
//                        }else if(obj instanceof DLTaggedObject){
//                            DLTaggedObject d = (DLTaggedObject)obj;
//                            valueoth = d.toString().substring(d.toString().indexOf("]")+1);
//
////                                System.out.println(">>getTagNo:"+d.toString()+" , "+valueoth);
//                        }
//
//                    }
                    
                }
                
                
                
            }
        }
    }

    private String getX500Field(String asn1ObjectIdentifier, X500Name x500Name) {
        RDN[] rdnArray = x500Name.getRDNs(new ASN1ObjectIdentifier(asn1ObjectIdentifier));

        String retVal = null;
        for (RDN item : rdnArray) {
            retVal = item.getFirst().getValue().toString();
        }
        return retVal;
    }

    private PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(InputStream pem) {
        Security.addProvider(new BouncyCastleProvider());
        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream = null;

        pemStream = (ByteArrayInputStream) pem;

        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = null;
        try {
            pemParser = new PEMParser(pemReader);
            Object parsedObj = pemParser.readObject();
            System.out.println("PemParser returned: " + parsedObj);
            System.out.println("PemParser returned: " + parsedObj.getClass());
            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObj;
            }
        } catch (IOException ex) {
            System.out.println("IOException, convertPemToPublicKey"+ ex.getMessage());
        } finally {
            if (pemParser != null) {
                IOUtils.closeQuietly(pemParser);
            }
        }
        return csr;
    }
    
        
    private void getsubjectAlternativeName(PKCS10CertificationRequest csr) throws IOException{
        
        Attribute[] certAttributes = csr.getAttributes();
        for (Attribute attribute : certAttributes) {
            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {

                Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
                GeneralNames gns = GeneralNames.fromExtensions(extensions,Extension.subjectAlternativeName);
                System.out.println(">>san GeneralNames:"+gns);
                

                Extension ext = extensions.getExtension(Extension.subjectAlternativeName);
                GeneralName[] names = gns.getNames();
                for(int k=0; k < names.length; k++) {
                    String title = "";
                    String value = "";

                    if(names[k].getTagNo() == GeneralName.rfc822Name) {
                        title = "rfc822Name";
                        value = names[k].getName().toString();
                    }else if(names[k].getTagNo() == GeneralName.dNSName) {
                        title = "dNSName";
                        value = names[k].getName().toString();
                    }else if(names[k].getTagNo() == GeneralName.directoryName) {
                        title = "directoryName";
                        value = names[k].getName().toString();
                    }else if(names[k].getTagNo() == GeneralName.x400Address) {
                        title = "x400Address";
                        value = names[k].getName().toString();
                    }else if(names[k].getTagNo() == GeneralName.ediPartyName) {
                        title = "ediPartyName";
                        value = names[k].getName().toString();
                    }else if(names[k].getTagNo() == GeneralName.uniformResourceIdentifier) {
                        title = "uniformResourceIdentifier";
                        value = names[k].getName().toString();
                    }else if(names[k].getTagNo() == GeneralName.iPAddress) {
                        title = "iPAddress";
                        value = new String(DEROctetString.getInstance(names[k].getName()).getOctets());
                        
                        byte[] ipAddressBytes = ((ASN1OctetString) names[k].getName()).getOctets();
                        String ipAddressString = "";
                        ipAddressString = InetAddress.getByAddress(ipAddressBytes).getHostAddress();
                        
                    }else if(names[k].getTagNo() == GeneralName.registeredID) {
                        title = "registeredID";
                        value = names[k].getName().toString();
                    }else if(names[k].getTagNo() == GeneralName.otherName) {
                        title = "otherName";
                        
                        ASN1Sequence otherName = (ASN1Sequence) names[k].getName();
                        Iterator i = otherName.getObjects().asIterator();
                        String oidoth = "";
                        String valueoth = "";
                        while(i.hasNext()){

                            Object obj = i.next();
                            if(obj instanceof ASN1ObjectIdentifier){
                                ASN1ObjectIdentifier objiden = (ASN1ObjectIdentifier) obj;
//                                System.out.println(">>ASN1ObjectIdentifier:"+objiden.getId());
                                
                                oidoth = objiden.getId();
                            }else if(obj instanceof DLTaggedObject){
                                DLTaggedObject d = (DLTaggedObject)obj;
                                valueoth = d.toString().substring(d.toString().indexOf("]")+1);
                                
//                                System.out.println(">>getTagNo:"+d.toString()+" , "+valueoth);
                            }

                        }
                        
                        value = oidoth+"#@#"+valueoth;
                        
                        
                    }
                    System.out.println(">>san :"+title + ": "+ value);
                }
            }
       }
    }
    
    
    private void getSMIME(PKCS10CertificationRequest csr) throws IOException, Exception{
        
        
        Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if( attrs.length != 1 ) {
            System.out.println("bad");
            return;
        }
        ASN1Encodable[] valus = attrs[0].getAttributeValues();
        if( valus.length != 1 ){
            System.out.println("bad");
            return;
        }
        Extension extn = Extensions.getInstance(valus[0]).getExtension(PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities);
        if( extn == null ){
            System.out.println("missing");
            return;
        }else {
            ASN1Encodable asn1 = extn.getParsedValue();
            System.out.println("getExtnValue:"+asn1.toString());
            
            ArrayList<HashMap<String,String>> al = new ArrayList();
            JSONArray jsonarray = new JSONArray(asn1.toString());
            for (int i = 0; i < jsonarray.length(); i++) {
                JSONArray jsarrvalue = new JSONArray(jsonarray.getString(i));
                System.out.println(">>toString:"+jsarrvalue+" ,"+jsarrvalue.length()+" , "+jsarrvalue.getString(0)+" , "+jsarrvalue.getString(1));

                HashMap<String,String> hm = new HashMap<>();
                for (int j = 0; j < jsarrvalue.length(); j++){
                    hm.put(Integer.toString(j), jsarrvalue.getString(j));
                }
                al.add(hm);
            }
        }
        
        
        
        
        
        // to get the _value_ of the extension, now extn.getExtnValus().getOctets()
        // to _use_ the _value_ of the extension, parse as GeneralNames:
//        GeneralNames sanv = GeneralNames.getInstance(extn.getExtnValue().getOctets());
//        for( GeneralName item : sanv.getNames() ){ // example of possible usage
//            System.out.println (item.toString()); // you probably want something else
//        }
//        Attribute[] certAttributes = csr.getAttributes();
//        for (Attribute attribute : certAttributes) {
//
//            System.out.println(attribute.getAttrType()+" , "+PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities);
//
//            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities)) {
//
//                Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
//                GeneralNames gns = GeneralNames.fromExtensions(extensions,Extension.subjectAlternativeName);
//                System.out.println(">>getSMIME GeneralNames:"+gns);
//
//            }
//        }
//        CertificationRequest r = csr.toASN1Structure();
//        SubjectPublicKeyInfo pkInfo = r.getCertificationRequestInfo().getSubjectPublicKeyInfo();
//        System.out.println(">>getSMIME GeneralNames:"+pkInfo.getAlgorithmId().getParameters());
//
//        ASN1Set attributes = r.getCertificationRequestInfo().getAttributes();
//        for (int i = 0; i != attributes.size(); i++) {
//            Attribute attr = Attribute.getInstance(attributes.getObjectAt(i));
//
//            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
//                X509Extensions extensions = X509Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
//
//                Enumeration e = extensions.oids();
//                while (e.hasMoreElements()) {
////                    DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
////                    X509Extension ext = extensions.getExtension(oid);
////
////                    certGen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
//                }
//            }
//        }
        //Attribute[] certAttributes = csr.getAttributes(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities.toString()));
//        Attribute[] certAttributes = csr.getAttributes();
//
//        for (Attribute attribute : certAttributes) {
//
////            Extensions extensions = Extensions.getInstance(attribute.getAttrValues());
////            GeneralNames gns = GeneralNames.fromExtensions(extensions,Extension.subjectAlternativeName);
//            System.out.println(">>getSMIME GeneralNames:"+attribute.getAttrType());
//
//
////            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities)) {
////
////
////                Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
////                GeneralNames gns = GeneralNames.fromExtensions(extensions,Extension.subjectAlternativeName);
////                System.out.println(">>getSMIME GeneralNames:"+gns);
////
////            }
//        }
        
        
        
        
        
        // to get the _value_ of the extension, now extn.getExtnValus().getOctets()
        // to _use_ the _value_ of the extension, parse as GeneralNames:
//        GeneralNames sanv = GeneralNames.getInstance(extn.getExtnValue().getOctets());
//        for( GeneralName item : sanv.getNames() ){ // example of possible usage
//            System.out.println (item.toString()); // you probably want something else
//        }
        
        
        
//        Attribute[] certAttributes = csr.getAttributes();
//        for (Attribute attribute : certAttributes) {
//            
//            System.out.println(attribute.getAttrType()+" , "+PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities);
//            
//            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities)) {
//                
//                Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
//                GeneralNames gns = GeneralNames.fromExtensions(extensions,Extension.subjectAlternativeName);
//                System.out.println(">>getSMIME GeneralNames:"+gns);
//                
//            }
//        }
        
//        CertificationRequest r = csr.toASN1Structure();
//        SubjectPublicKeyInfo pkInfo = r.getCertificationRequestInfo().getSubjectPublicKeyInfo();
//        System.out.println(">>getSMIME GeneralNames:"+pkInfo.getAlgorithmId().getParameters());
//        
//        ASN1Set attributes = r.getCertificationRequestInfo().getAttributes();
//        for (int i = 0; i != attributes.size(); i++) {
//            Attribute attr = Attribute.getInstance(attributes.getObjectAt(i));
//            
//            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
//                X509Extensions extensions = X509Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
//
//                Enumeration e = extensions.oids();
//                while (e.hasMoreElements()) {
////                    DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
////                    X509Extension ext = extensions.getExtension(oid);
////
////                    certGen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
//                }
//            }  
//        }
        
        
        

        //Attribute[] certAttributes = csr.getAttributes(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities.toString()));
//        Attribute[] certAttributes = csr.getAttributes();
//        
//        for (Attribute attribute : certAttributes) {
//            
////            Extensions extensions = Extensions.getInstance(attribute.getAttrValues());
////            GeneralNames gns = GeneralNames.fromExtensions(extensions,Extension.subjectAlternativeName);
//            System.out.println(">>getSMIME GeneralNames:"+attribute.getAttrType());
//            
//            
////            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities)) {
////                
////                
////                Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
////                GeneralNames gns = GeneralNames.fromExtensions(extensions,Extension.subjectAlternativeName);
////                System.out.println(">>getSMIME GeneralNames:"+gns);
////                
////            }
//        }
    }

    
    public static String parseUPN(GeneralName generalName) {
        // OtherName ::= SEQUENCE {
        //    type-id OBJECT IDENTIFIER,
        //    value [0] EXPLICIT ANY DEFINED BY type-id }

        String UPN_OID = "1.3.6.1.4.1.311.20.2.3";
        ASN1Sequence otherName = (ASN1Sequence) generalName.getName();
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) otherName.getObjectAt(0);

        System.out.println("oid:"+oid.getId());
        
        if (UPN_OID.equals(oid.getId())) {
            
            String result = "";
            Iterator i = otherName.getObjects().asIterator();
            while(i.hasNext()){
                
                Object obj = i.next();
                if(obj instanceof ASN1ObjectIdentifier){
                    ASN1ObjectIdentifier objiden = (ASN1ObjectIdentifier) obj;
                    System.out.println(">>ASN1ObjectIdentifier:"+objiden.getId());
                }else if(obj instanceof DLTaggedObject){
                    DLTaggedObject d = (DLTaggedObject)obj;
                    System.out.println(">>getTagNo:"+d.toString());
                    
                    return d.toString();
                }
            }
        }

        
        // fallback to generic handling
        ASN1Encodable value = otherName.getObjectAt(1);
        try {
            //return oid.getId()+","+HexUtil.getHexString(value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            return oid.getId()+","+Hex.toHexString(value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        } catch (IOException e) {
            return oid.getId();
        }

    }
}
