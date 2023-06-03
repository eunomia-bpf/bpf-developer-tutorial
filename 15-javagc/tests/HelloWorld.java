public class HelloWorld {
    public static void main(String[] args) {
        // loop and sleep for 1 second
        while (true) {
            System.out.println("Hello World!");
            // create an object and let it go out of scope
            Object obj = new Object();
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
