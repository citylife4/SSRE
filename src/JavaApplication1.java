/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.logging.*;



/**
 *
 * @author root
 */
public class JavaApplication1 {


    /**
     * @param args the command line arguments
     * 
     */
    public static void main(String[] args) {
        
        


        try {
            //Get last provider for cartao de cidadao
            Provider prov = Security.getProviders()[9];
            /*for(int i = 0; i < provs.length; i++){
                System.out.println( i + " - Nome do provider: " + provs[i].getName() );
            }*/
            
            //Ver Provider:
            System.out.println(prov.getName());

            //Criar keystore
            KeyStore ks = KeyStore.getInstance( "PKCS11", prov );
            ks.load( null, null );
            
            //Percorrer aliases
            Enumeration<String> als = ks.aliases();
            
            /*while (als.hasMoreElements()){
                System.out.println( als.nextElement() );
            }*/
            
            Enumeration aliasesEnum = ks.aliases();
            
            //Ver certificados e etc do cartao
            
            //while (aliasesEnum.hasMoreElements()) {
                String alias = (String)aliasesEnum.nextElement();
                System.out.println("Alias: " + alias);
                X509Certificate cert = 
                (X509Certificate) ks.getCertificate(alias);
               // System.out.println("Certificate: " + cert);
                PrivateKey privateKey =
                   (PrivateKey) ks.getKey(alias, null);
                System.out.println("Private key: " + privateKey);
                System.out.println("Signature: " + 
                        Arrays.toString(cert.getSignature()));
             //}

            
            Signature dsa = Signature.getInstance("SHA512withRSA", prov);
            
            PublicKey pub = cert.getPublicKey();
            
            dsa.initSign(privateKey);
             
            
            FileInputStream datafis = new FileInputStream("Tobesiggn");
            try (BufferedInputStream bufin = new BufferedInputStream(datafis)) {
                byte[] buffer = new byte[1024];
                int len;
                while (bufin.available() != 0) {
                    len = bufin.read(buffer);
                    dsa.update(buffer, 0, len);
                }
            } catch (SignatureException ex) {
                Logger.getLogger(JavaApplication1.class.getName())
                        .log(Level.SEVERE, null, ex);
            }
            
            //boolean verifies = sig.verify(sigToVerify);

            System.out.println("signature verifies: " );
            
            byte[] realSig = dsa.sign();

        
            try ( /* to Save the signature in a file */ 
                FileOutputStream sigfos = new FileOutputStream("sig")) {
                sigfos.write(realSig);
            }


            /* Save the public key in a file */
            byte[] key = pub.getEncoded();
            try (FileOutputStream keyfos = new FileOutputStream("suepk")) {
                keyfos.write(key);
                //System.out.println("OLA\n\n" + ks.getCertificate(alias));
                //Signature sig = new Signature;
            }
            
            
       
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException 
               | CertificateException | UnrecoverableKeyException
               | InvalidKeyException e) {
            System.err.println("EXCEPTION CATCH: ");
            Logger.getLogger(JavaApplication1.class.getName()).log(Level.SEVERE, null, e);
        } catch (SignatureException ex) {
            Logger.getLogger(JavaApplication1.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    

 
    
}




