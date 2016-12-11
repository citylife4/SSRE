/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package card;

import com.sun.javafx.PlatformUtil;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.util.Pair;

/**
 *
 * @author José Valverde
 */
public class cardClass {

    private KeyStore ks;
    private Provider p;
    
    
    public cardClass() {
    }
    
    /**
     *
     */
    public void init() {
       Pair returned = loadPkcs11();
           
       ks = (KeyStore) returned.getKey();
       p = (Provider) returned.getValue();
    }
    
   
    public boolean signData(
            String filetoSign, String fileWithSign, String fileWithPub) {

        try {


               //Get Last Certificate - Signature
        for (Enumeration e =  ks.aliases(); e.hasMoreElements( );)
                                    System.out.println("\t" + e.nextElement( ));

        //Get Private Key
        PrivateKey pk = 
                (PrivateKey) ks.getKey("CITIZEN SIGNATURE CERTIFICATE", null);

        //Get signature with SHA256withRSA algorithm
        Signature s = Signature.getInstance("SHA256withRSA");

        //Initialize signature with private key from smartCard
        s.initSign(pk);

        //Get X509Certificate
        X509Certificate cert = 
            (X509Certificate) ks.getCertificate("CITIZEN SIGNATURE CERTIFICATE");

        System.out.println("Cert: " + cert.getSigAlgName());

        //Get certificate publicKey
        PublicKey pub = cert.getPublicKey();



        //Try to sign file


        FileInputStream datafis = new FileInputStream(filetoSign);
        try (BufferedInputStream bufin = new BufferedInputStream(datafis)) {
            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                s.update(buffer, 0, len);
            }
            System.out.println("buffer: " + Arrays.toString(buffer));
        }

        //Create file with cverification digital
        /*
        Path path = Paths.get("cert", "cert");
                    Files.createDirectories(path.getParent());
                    DataOutputStream fos = new DataOutputStream(Files.newOutputStream(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE));
                    ObjectOutputStream oos = new ObjectOutputStream(fos);

        */

        //Creating signature
        byte[] realSig = s.sign();


        try ( // to Save the signature in a file  
            FileOutputStream sigfos = new FileOutputStream(fileWithSign)) {
            sigfos.write(realSig);
        }


        // Save the public key in a file 
        byte[] key = pub.getEncoded();
        try (FileOutputStream keyfos = new FileOutputStream(fileWithPub)) {
            keyfos.write(key);
            //System.out.println("OLA\n\n" + ks.getCertificate(alias));
            //Signature sig = new Signature;
        }

        return true;
            
        } catch (IOException | InvalidKeyException | KeyStoreException 
                 | NoSuchAlgorithmException | SignatureException 
                 | UnrecoverableKeyException e) {
            
            System.err.println("EXCEPTION: ");
            Logger.getLogger(cardClass.class.getName()).log(Level.SEVERE, null, e);
            return false;
        }

         
     }
    
    public boolean verifySignature(
            String filetoVerify, String fileWithSign, String fileWithPub) {
              
        try{
            
            byte[] encKey;
            try ( 
                FileInputStream keyfis = new FileInputStream(fileWithPub)) {
                encKey = new byte[keyfis.available()];
                keyfis.read(encKey);
            }



            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);

            System.out.println("pubKeySpec.getFormat():" + pubKeySpec.toString());

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);


            byte[] sigToVerify;
            try ( /* input the signature bytes */ 
                FileInputStream sigfis = new FileInputStream(fileWithSign)) {
                sigToVerify = new byte[sigfis.available()];
                sigfis.read(sigToVerify );
            }

            /* create a Signature object and initialize it with the public key */
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(pubKey);

            /* Update and verify the data */
            FileInputStream dataSigned = new FileInputStream(filetoVerify);
            try (BufferedInputStream bufin = new BufferedInputStream(dataSigned)) {
                byte[] buffer = new byte[1024];
                int len;
                while (bufin.available() != 0) {
                    len = bufin.read(buffer);
                    sig.update(buffer, 0, len);
                }
            }


            boolean verifies = sig.verify(sigToVerify);

            System.out.println("Signature verifies: " + verifies);
            return verifies;



    } catch (IOException | NoSuchAlgorithmException 
           | InvalidKeyException | InvalidKeySpecException | SignatureException e) {

        System.err.println("EXCEPTION: ");
        Logger.getLogger(cardClass.class.getName())
                .log(Level.SEVERE, null, e);
        return false;
    }
}
    
    private Pair<KeyStore,Provider> loadPkcs11(){
    String pkcs11ConfigSettings;
        
        if (PlatformUtil.isWindows()){
                 pkcs11ConfigSettings ="name = CartaoCidadao\n" 
                         + "library = C:\\Windows\\system32\\pteidpkcs11.dll";			
        }else {
                 pkcs11ConfigSettings ="name = CartaoCidadao\n" 
                         + "library = /usr/local/lib/libpteidpkcs11.so";			
        }
		
	byte[] pkcs11configBytes = pkcs11ConfigSettings.getBytes();
	ByteArrayInputStream configStream = 
                new ByteArrayInputStream(pkcs11configBytes);
	 
	final Provider p = new sun.security.pkcs11.SunPKCS11(configStream);
	Security.addProvider(p);
	KeyStore ks = null;
	
	try {

            ks = KeyStore.getInstance("PKCS11");				
            ks.load(null,null);

            for (Enumeration e =  ks.aliases(); e.hasMoreElements( );)
                            System.out.println("\t" + e.nextElement( ));


                
	} catch (IOException | KeyStoreException 
                | NoSuchAlgorithmException | CertificateException e1) {
            System.err.print("[loadPkcs11]: ");
            Logger.getLogger(cardClass.class.getName())
                    .log(Level.SEVERE, null, e1);

	}
	
        Pair toReturn = new Pair<>(ks,p);
	return toReturn;			 
	
	}
}
