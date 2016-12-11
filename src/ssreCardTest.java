import com.sun.javafx.PlatformUtil;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.logging.*;
import javafx.util.Pair;
import javax.swing.JOptionPane;



/**
 *
 * @author José Valverde
 */
public class ssreCardTest {


    /**
     * @param args the command line arguments
     * 
     */
    public static void main(String[] args)  {

        /*
        if(args.length < 5)
        {
            System.err.println("No Arguments defined");
            System.out.println("Usage: java - jar CCsignature\n"
                    + "\t\tArgs to verify signature: verify toVerifyFilename "
                    + "signatureFilename publickeyFilename\n"
                    + "\t\tArgs to sign file: sign toSignFilename "
                    + "filenameToSaveSignature filenameToSavePublicKey");
            return ;
        }
        
        */
        
           //Criar keystore
           Pair returned = loadPkcs11();
           
           KeyStore ks = (KeyStore) returned.getKey();
           Provider p = (Provider) returned.getValue();

            
        try {
            //Percorrer aliases
            Enumeration<String> als = ks.aliases();
        } catch (KeyStoreException ex) {
            Logger.getLogger(ssreCardTest.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
            
                  
            
            
            signData(p, ks, "tobesiggn", "sig", "pub");
            verifySignature(p, ks, "tobesiggn", "sig", "pub");
            
            /*if(args[0].equals("sign"))
                signData(p, ks, args[1], args[2], args[3]);
            else
                verifySignature(p, ks, args[1], args[2], args[3]);
            */
           /* 
            Enumeration aliasesEnum = ks.aliases();
            
            //Ver Conteudo do Cartão
            while (aliasesEnum.hasMoreElements()) {
                String alias = (String)aliasesEnum.nextElement();
                System.out.println("Alias: " + alias);
                X509Certificate cert = 
                (X509Certificate) ks.getCertificate(alias);
               //System.out.println("Certificate: " + cert);
                PrivateKey privateKey =
                   (PrivateKey) ks.getKey(alias, null);
                System.out.println("Private key: " + privateKey);
             }
            */
               
 
            
            
            //Now verify
            
        
    }
    
    /**
     * Loads PKCS#11 library for CC
     * @return Keystore with CC certificates
     */
    
     private static Pair<KeyStore,Provider> loadPkcs11(){
	 
        
        
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
            JOptionPane.showMessageDialog(null, e1, "InfoBox: " + "Verify", JOptionPane.INFORMATION_MESSAGE);


	}
	
        Pair toReturn = new Pair<>(ks,p);
	return toReturn;			 
	
	}


     
    public static boolean signData(Provider p, KeyStore ks, 
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
            JOptionPane.showMessageDialog(null, e, "InfoBox: " + "Verify", JOptionPane.INFORMATION_MESSAGE);
            Logger.getLogger(ssreCardTest.class.getName()).log(Level.SEVERE, null, e);
            return false;
        }

         
     }
    
    public static boolean verifySignature(Provider p, KeyStore ks,
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
        JOptionPane.showMessageDialog(null, e, "InfoBox: " + "Verify", JOptionPane.INFORMATION_MESSAGE);
        Logger.getLogger(ssreCardTest.class.getName())
                .log(Level.SEVERE, null, e);
        return false;
    }
        
  
    
    }
}







