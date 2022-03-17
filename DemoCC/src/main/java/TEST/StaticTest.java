package TEST;


public class StaticTest implements Hello {
    public void morning(String name) {
        System.out.println("Good morning! " + name);
    }

    public static void main(String[] args) {

        Hello hello = new StaticTest();
        hello.morning("uu");

        Hello hello1 = new StaticTest1();
        hello1.morning("oo");
    }

}
