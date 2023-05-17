package controllers;


import cryptography.Certfile;
import cryptography.Cryptography;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;
import quiz.Question;
import quiz.Quiz;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

public class QuizController {
    private ArrayList<Question> questions=new ArrayList<>();
    static int i=0,numberOfTrueAnswers=0;




    @FXML
    private ListView<String> answersListView;

    @FXML
    private TextArea questionTextArea;

    @FXML
    private TextField answereTextField;

    @FXML
    private Button nextQuestionButton;

    @FXML
    private TextField resultTextField;

    @FXML
    private Label resultLabela;

    @FXML
    private Button exitButton;


    @FXML
    private Button resultButton;

    @FXML
    private Label currentResultLabel;


    Stage stage;
    String userName;
    long begin;
    long end;
    long workingTime;
    public QuizController(Stage stage, String userName) {this.stage=stage;
    this.userName=userName;}




    @FXML
    private void initialize(){
        numberOfTrueAnswers=0;
        i=0;
        try {


        questions= Quiz.listQuestionsForQuiz();
        begin = System.currentTimeMillis();

            }
        catch (IndexOutOfBoundsException indexOutOfBoundsException){
            indexOutOfBoundsException.printStackTrace();
        }


            if (questions.get(0).getHaveAnswer()==true){
                resultTextField.setText(Integer.toString(numberOfTrueAnswers));
                resultButton.setVisible(false);
                exitButton.setVisible(false);
                resultLabela.setVisible(false);
                answereTextField.setVisible(false);
                answersListView.setVisible(true);
                questionTextArea.setText(questions.get(0).getQuestion());
                ArrayList<String> answers=new ArrayList<>();
                answers.add("1. " + questions.get(0).getAnswer1());
                answers.add("2. " + questions.get(0).getAnswer2());
                answers.add("3. " + questions.get(0).getAnswer3());
                answers.add("4. " + questions.get(0).getAnswer4());
                ObservableList<String> items = FXCollections.observableArrayList(answers);
                answersListView.setItems(items);
                i++;

            }
            else{

                resultTextField.setText(Integer.toString(numberOfTrueAnswers));
                resultButton.setVisible(false);
                exitButton.setVisible(false);
                answersListView.setVisible(false);
                answereTextField.setVisible(true);
                resultLabela.setVisible(true);
                questionTextArea.setText(questions.get(0).getQuestion());
                i++;

            }
        }

    @FXML
    void showNextQuestion(MouseEvent event) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        if (questions.get(i-1).getHaveAnswer()==true){
            String userAnswer=answersListView.getSelectionModel().getSelectedItem();
            if (userAnswer.substring(3,userAnswer.length()).equalsIgnoreCase(questions.get(i-1).getTrueAnswer())){
                numberOfTrueAnswers++;
            }
        }

        else {
              if(  answereTextField.getText().equalsIgnoreCase(questions.get(i-1).getTrueAnswer())){
                  numberOfTrueAnswers++;
              }
        }

        questionTextArea.setText(null);
        answersListView.setItems(null);
        answereTextField.setText(null);
        if (i==5){
            end = System.currentTimeMillis();
            nextQuestionButton.setVisible(false);
            resultButton.setVisible(true);
            exitButton.setVisible(true);
            questionTextArea.setVisible(false);
            answereTextField.setVisible(false);
            resultLabela.setVisible(false);
            answersListView.setVisible(false);
            resultTextField.setText(Integer.toString(numberOfTrueAnswers));
            workingTime=end-begin;
            currentResultLabel.setText("Ukupan broj tacnih odgovora ");
           // byte [] bytes1=Cryptography.encryptFileSymmetricAlgorithm(Cryptography.getDecryptionLocationResult(),Cryptography.getEncryptionLocationResult(),Cryptography.getSessionKey(),Cryptography.getAlgorithmName(),Cryptography.getAlgorithmKey(),16,16);
            byte [] bytes= Cryptography.decryptFileWithSymmetricAlgorithm(Cryptography.getEncryptionLocationResult(),Cryptography.getDecryptionLocationResult(),Cryptography.getSessionKey(),Cryptography.getAlgorithmName(),Cryptography.getAlgorithmKey(),16,16);
            SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
            Date date = new Date();
            String dateToSting=formatter.format(date) +"   (" + workingTime/1000 + "s)";
            Quiz.writeQuizResultInFile(userName,dateToSting,Integer.toString(numberOfTrueAnswers));
            byte [] bytes3=Cryptography.encryptFileSymmetricAlgorithm(Cryptography.getDecryptionLocationResult(),Cryptography.getEncryptionLocationResult(),Cryptography.getSessionKey(),Cryptography.getAlgorithmName(),Cryptography.getAlgorithmKey(),16,16);
            Certfile.deleteFileOnSomePath(Cryptography.getDecryptionLocationResult());
        }


        else if (questions.get(i).getHaveAnswer()==true){
            resultTextField.setText(Integer.toString(numberOfTrueAnswers));
            resultButton.setVisible(false);
            exitButton.setVisible(false);
            resultLabela.setVisible(false);
            answereTextField.setVisible(false);
            answersListView.setVisible(true);
            questionTextArea.setText(questions.get(i).getQuestion());
            ArrayList<String> answers=new ArrayList<>();
            answers.add("1. " + questions.get(i).getAnswer1());
            answers.add("2. " + questions.get(i).getAnswer2());
            answers.add("3. " + questions.get(i).getAnswer3());
            answers.add("4. " + questions.get(i).getAnswer4());
            ObservableList<String> items = FXCollections.observableArrayList(answers);
            answersListView.setItems(items);
            i++;

        }
        else {
            resultLabela.setVisible(true);
            resultTextField.setText(Integer.toString(numberOfTrueAnswers));
            resultButton.setVisible(false);
            exitButton.setVisible(false);
            answersListView.setVisible(false);
            questionTextArea.setText(questions.get(i).getQuestion());
            resultTextField.setVisible(true);
            answereTextField.setVisible(true);
            i++;

        }


        }



    @FXML
    void showLoginForm(MouseEvent event) throws IOException {


        FXMLLoader loader = new FXMLLoader(getClass().getResource(".." + File.separator + "views" + File.separator + "loginForm.fxml"));
        LoginController loginController = new LoginController(stage);
        loader.setController(loginController);
        Parent root = loader.load();
        stage.setTitle("Quiz");
        stage.setScene(new Scene(root));
        stage.show();


    }

    @FXML
    void showAllResult(MouseEvent event) throws IOException {

        Stage newStage=new Stage();
        FXMLLoader loader = new FXMLLoader(getClass().getResource(".." + File.separator + "views" + File.separator + "resultForm.fxml"));
        ResultController resultControllerr = new ResultController(newStage);
        loader.setController(resultControllerr);
        Parent root = loader.load();
        newStage.setTitle("QuizResult");
        newStage.setScene(new Scene(root));
        newStage.show();



    }


}


