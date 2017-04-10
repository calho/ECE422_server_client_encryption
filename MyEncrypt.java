import java.util.Arrays;

public class MyEncrypt {

public native void encrypt(int[] v, int[] k);

public MyEncrypt(){
}

public void run(int[] v, int[] k) {
	System.out.println("before encrypt inside encrypt class: " + Arrays.toString(v));

	encrypt(v, k);

	System.out.println("after encrypt inside encrypt class: " + Arrays.toString(v));
}

}
