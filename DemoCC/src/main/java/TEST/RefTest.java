package TEST;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class RefTest {

    public static void main(String[] args) throws IOException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, ClassNotFoundException {

//        Runtime.getRuntime().exec("calc.exe");

//        Runtime.class.getMethod("exec", String.class).invoke(Runtime.getRuntime(), "calc.exe");
//
//        Class.forName("java.lang.Runtime").getMethod("exec", String.class)
//                .invoke(Runtime.getRuntime(),"calc.exe");

        Runtime o = (Runtime) Runtime.class.getMethod("getRuntime", null).invoke(null, null);
        o.exec("calc.exe");

    }
}
