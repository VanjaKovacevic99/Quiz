package cryptography;

import javafx.scene.Parent;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import java.security.KeyPair;

public class MyRequest {

    private PKCS10CertificationRequest pkcs10CertificationRequest;
    private KeyPair keyPair;

    public MyRequest(PKCS10CertificationRequest pkcs10CertificationRequest, KeyPair keyPair){
        this.pkcs10CertificationRequest=pkcs10CertificationRequest;
        this.keyPair=keyPair;
    }
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public void setPkcs10CertificationRequest(PKCS10CertificationRequest pkcs10CertificationRequest){
        this.pkcs10CertificationRequest=pkcs10CertificationRequest;
    }

   public PKCS10CertificationRequest getPkcs10CertificationRequest(){
        return  pkcs10CertificationRequest;

   }

   public KeyPair getKeyPair(){
        return keyPair;
   }
}
