package TEST;

import java.lang.reflect.InvocationHandler;
        import java.lang.reflect.Method;
        import java.lang.reflect.Proxy;

public class ProxyTest {
    public static void main(String[] args){

        // 定义了一个handler，来实现对某个类接口的调用。
        InvocationHandler handler = new InvocationHandler() {

            // 里面定义了代理对象需要执行的操作
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                if (method.getName().equals("morning")) {
                    System.out.println("Good morning！" + args[0]);
                }
                return null;
            }
        };

        // 定义了一个代理对象hello 传入 ClassLoader、想要代理的接口、和调用接口时触发的方法
        Hello hello = (Hello)Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),new Class[]{Hello.class},handler);
        hello.morning("oo");  // 调用hello.morning,就会触发handler的invoke方法

        // nice day！
        InvocationHandler handler1 = new InvocationHandler() {

            // 里面定义了代理对象需要执行的操作
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                if (method.getName().equals("morning")) {
                    System.out.println("Have a nice day! " + args[0]);
                }
                return null;
            }
        };

        Hello hello1 = (Hello)Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),new Class[]{Hello.class},handler1);
        hello1.morning("uu");


    }
}