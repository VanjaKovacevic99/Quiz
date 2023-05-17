package quiz;

import cryptography.Steganography;

import java.io.*;
import java.util.ArrayList;

import java.util.Date;
import java.util.Random;

public class Quiz {

        private static final String resultLocation= "src" + File.separator + "result";
    public static ArrayList<String> getAllFileNameFromFile(File fileName){
        ArrayList<String> results = new ArrayList<String>();


        File[] files = new File(fileName.getPath()).listFiles();
        //If this pathname does not denote a directory, then listFiles() returns null.

        for (File file : files) {
            if (file.isFile()) {
                results.add(file.getName());
            }
        }
        return results;
    }


    public static void encodeImage(File file, File fileWithQuestion) throws IndexOutOfBoundsException{
        ArrayList<String> imageName=getAllFileNameFromFile(new File(file.getPath()));
        ArrayList<String> arrayList=new ArrayList<>();
        try
        {
            File fileQuestions=new File(fileWithQuestion.getPath());
            FileReader fileReader=new FileReader(fileQuestions);
            BufferedReader bufferedReader=new BufferedReader(fileReader);
            String line;
            while((line=bufferedReader.readLine())!=null)
            {
             arrayList.add(line);

            }
            fileReader.close();

        }
        catch(IOException e)
        {
            e.printStackTrace();
        }

        for (int i=0;i<imageName.size();i++){
            Steganography.encode(new File("src" + File.separator + "image" + File.separator + imageName.get(i)),arrayList.get(i));
        }
    }


    public static ArrayList<Question> listQuestionsForQuiz() throws IndexOutOfBoundsException {
        String question = null;
        Boolean isHaveAnswer = false;
        String answer1 = null;
        String answer2 = null;
        String answer3 = null;
        String answer4 = null;
        String trueAnswer = "";
        ArrayList<String> allImage = getAllFileNameFromFile(new File("src" + File.separator + "image" + File.separator + "questions"));
        ArrayList<Question> questions = new ArrayList<>();
        ArrayList<Integer> randomNumbers=getRandomNonRepeatingIntegers(5,0,19);
        for (int i = 0; i < 5; i++) {

            String decodeQuestion = Steganography.decode(new File("src" + File.separator + "image" + File.separator + "questions" + File.separator + allImage.get(randomNumbers.get(i))));

            if (decodeQuestion.substring(0, 1).equals("*")) {
                isHaveAnswer = false;
                question = decodeQuestion.substring(1, decodeQuestion.indexOf("#"));
                trueAnswer = decodeQuestion.substring(decodeQuestion.indexOf("#") + 1, decodeQuestion.lastIndexOf("#"));
                questions.add(new Question(question, isHaveAnswer, answer1, answer2, answer3, answer4, trueAnswer));
            } else {
                isHaveAnswer = true;
                String[] arrOfStr = decodeQuestion.split("\\#");
                questions.add(new Question(arrOfStr[0],isHaveAnswer,arrOfStr[1],arrOfStr[2],arrOfStr[3],arrOfStr[4],arrOfStr[5]));

            }



        }
        return questions;

    }

    
    public static ArrayList<Integer> getRandomNonRepeatingIntegers(int numberOfNeedNumbers, int min, int max) {
        Random random = new Random();
        ArrayList<Integer> numbers = new ArrayList<Integer>();

        while (numbers.size() < numberOfNeedNumbers) {
            int randomNum = random.nextInt((max - min) + 1) + min;

            if (!numbers.contains(randomNum)) {
                numbers.add(randomNum);
            }
        }

        return numbers;
    }

    public static void writeQuizResultInFile(String userName, String dateTime, String result) throws IOException {
        File file = new File(resultLocation + File.separator + "result.txt");
        BufferedWriter bufferedWriter= new BufferedWriter(new FileWriter(file.getPath(),true));

        bufferedWriter.append(String.format(" %10s%65s%50s",userName,dateTime,result));
        bufferedWriter.newLine();
        bufferedWriter.flush();
        bufferedWriter.close();

    }
}

