/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.scc.rd.rdpki.testgenx509;

import java.util.ArrayList;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 *
 * @author terex
 */
public class NewMain {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        
        String[] s = new String[]{"rfc822name", "rfc822name@pki.summit.dev"};
        System.out.println(s.length); 
        
        System.out.println(SMIMECapability.rC2_CBC);
        System.out.println(PKCSObjectIdentifiers.RC2_CBC);
        
        
        
        SMIMECapabilityVector caps = new SMIMECapabilityVector();
        caps.addCapability(SMIMECapability.rC2_CBC, 128);
        caps.addCapability(SMIMECapability.dES_CBC);
        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
        
        System.out.println(">>"+new DERSequence(caps.toASN1EncodableVector()));

        ArrayList<String> altNames = new ArrayList<>();
        for(String san : altNames){
            
            switch (san) {
                case "1":
                    System.out.println("1");
                    break;
                case "2":
                    System.out.println("2");
                    break;
                case "3":
                    System.out.println("3");
                    break;
                case "4":
                    System.out.println("4");
                    break;
                default:
                    break;
            }
            
        }
        
        
    }
    
}
