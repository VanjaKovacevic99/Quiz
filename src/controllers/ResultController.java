package controllers;

import cryptography.Certfile;
import cryptography.Cryptography;
import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.stage.Stage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ResultController {
    @FXML
    private TextArea showResultTextArea;

    private static final String resultLocation="src" + File.separator + "result" + File.separator + "result.dec";
    Stage stage;
    public ResultController(Stage stage){
        this.stage=stage;
    }


    @FXML
    private void initialize() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        byte [] bytes= Cryptography.decryptFileWithSymmetricAlgorithm(Cryptography.getEncryptionLocationResult(),Cryptography.getDecryptionLocationResult(),Cryptography.getSessionKey(),Cryptography.getAlgorithmName(),Cryptography.getAlgorithmKey(),16,16);
        Certfile.deleteFileOnSomePath(Cryptography.getDecryptionLocationResult());
        String string=new String(bytes);
        showResultTextArea.setText(string);

}
}
