package App;

import controllers.LoginController;


import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.*;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {


        Security.addProvider(new BouncyCastleProvider());


        // Quiz.encodeImage(new File("src" + File.separator + "image"),new File("src" + File.separator + "pitanja.txt"));

        FXMLLoader loader = new FXMLLoader(getClass().getResource(".." + File.separator + "views" + File.separator + "loginForm.fxml"));
        LoginController loginController = new LoginController(primaryStage);
        loader.setController(loginController);
        Parent root = loader.load();
        primaryStage.setTitle("Quiz");
        primaryStage.setScene(new Scene(root));
        primaryStage.show();

    }





    public static void main(String[] args) {

            launch(args);
        }
}
