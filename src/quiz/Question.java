package quiz;

public class Question {
    String question=null;
    Boolean isHaveAnswer=false;
    String answer1;
    String answer2;
    String answer3;
    String answer4;
    String trueAnswer;

    public Question(){};

    public Question(String question, Boolean isHaveAnswer, String answer1, String answer2, String answer3, String answer4, String trueAnswer){
        this.question=question;
        this.isHaveAnswer=isHaveAnswer;
        this.answer1=answer1;
        this.answer2=answer2;
        this.answer3=answer3;
        this.answer4=answer4;
        this.trueAnswer=trueAnswer;
    }

    public String getQuestion() {
        return question;
    }

    public Boolean getHaveAnswer() {
        return isHaveAnswer;
    }

    public String getAnswer1() {
        return answer1;
    }

    public String getAnswer3() {
        return answer3;
    }

    public String getAnswer2() {
        return answer2;
    }

    public String getAnswer4() {
        return answer4;
    }

    public String getTrueAnswer() {
        return trueAnswer;
    }
}
