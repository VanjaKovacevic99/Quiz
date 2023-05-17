package controllers;

import cryptography.Certfile;
import cryptography.MyRequest;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import javafx.stage.Stage;


import java.io.File;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

public class LoginController {
    Stage stage;
    String userName;
    public LoginController(Stage stage) { this.stage=stage; }

    @FXML
    private PasswordField passwordTextField;

    @FXML
    private TextField userNameTextField;

    @FXML
    private TextArea pathTextArea;

    @FXML
    private Label singInLabel;

    @FXML
    private Button singInButton;

    @FXML
    private Button logInButton;

    @FXML
    private Button chooseCert;

    @FXML
    private Label messageLabela;

    @FXML
    private TextField chooseCertTextField;

    @FXML
    private PasswordField passLoginTextField;

    @FXML
    void showQuizForm(MouseEvent event) {

        FXMLLoader loader = new FXMLLoader(getClass().getResource(".." + File.separator + "views" + File.separator + "quizForm.fxml"));

        try {

            Certfile.isKeyStorePass(chooseCertTextField.getText(), passLoginTextField.getText());
            String caName=Certfile.getCAName(chooseCertTextField.getText(),passLoginTextField.getText()).substring(3,6);
            X509CRL x509CRL=Certfile.readCRLFromFile(caName);
            if (Certfile.isCertificateRevoked(x509CRL,Certfile.getCertFromKeyStore(chooseCertTextField.getText(),passLoginTextField.getText()))){
                messageLabela.setText("You can only log in three times !");
                chooseCertTextField.setText(null);
                passLoginTextField.setText(null);
            }
            else {
                Certfile.getCertFromKeyStore(chooseCertTextField.getText(), passLoginTextField.getText()).checkValidity();
                Certfile.replaceFileLine(chooseCertTextField.getText(), passLoginTextField.getText());
                userName = chooseCertTextField.getText().substring(0, chooseCertTextField.getText().indexOf("."));
                QuizController quizController = new QuizController(stage, userName);
                loader.setController(quizController);
                Parent root = loader.load();
                stage.setTitle("Quiz");
                stage.setScene(new Scene(root));
                stage.show();

            }
        } catch (Exception e){
            passLoginTextField.setText(null);
            messageLabela.setText("Invalid password !");
        }



    }


    @FXML
    void createCertificate(MouseEvent event) throws Exception {
        String [] caCert={"CA1.cer", "CA2.cer"};
        String [] caKeys={"CA1.key","CA2.key"};
        int numberCert=getRandomNumber(1,3)-1;
        if (userNameTextField.getText().isEmpty() || passwordTextField.getText().isEmpty()){
            singInLabel.setText("Unesite korisnicko ime i lozinku");
        }
        else {
            singInLabel.setText(null);
            MyRequest myRequest = Certfile.createCSR(userNameTextField.getText());
            X509Certificate x509Certificate=Certfile.x509ReqToX509(myRequest.getPkcs10CertificationRequest(), 365,Certfile.readPrivateKeyFromFile(caKeys[numberCert]),Certfile.readCertFromFile(caCert[numberCert]));
            Certfile.writePemCertToFile(x509Certificate,userNameTextField.getText());
            Certfile.exportKeyPairToKeystoreFile(myRequest.getKeyPair(),x509Certificate,userNameTextField.getText(),userNameTextField.getText(),passwordTextField.getText());
            File file=new File("src" + File.separator + "userPKCS12" + File.separator + userNameTextField.getText() + ".p12");
            pathTextArea.setText(file.getAbsolutePath());
            Certfile.writeUserToLoginFile(userNameTextField.getText(),"0");
            userNameTextField.setText(null);
            passwordTextField.setText(null);
        }



    }

    @FXML
    void chooseCertificate(MouseEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open KeyStore File");
        fileChooser.setInitialDirectory(new File("src" + File.separator + "userPKCS12Cert"));
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("PKCS12", "*.p12")
        );

        File selectedFile = fileChooser.showOpenDialog(stage);
        if (selectedFile != null) {
            String selectedFileName= selectedFile.getName();
            chooseCertTextField.setText(selectedFileName);


    }
    }

    public int getRandomNumber(int min, int max) {
        return (int) ((Math.random() * (max - min)) + min);
    }

}
