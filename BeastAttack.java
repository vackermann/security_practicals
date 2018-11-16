import java.io.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.util.Arrays;
import java.nio.ByteBuffer;

public class BeastAttack {

  public static long time;
  public static byte[] ciphertext;
  public static byte[] cToMatch = new byte[8];
  public static byte[] ivForC = new byte[8];

  public static void main(String[] args) throws Exception  {
  	ciphertext=new byte[1024]; // will be plenty big enough
    byte[] prefix = new byte[]{0,0,0,0,0,0,0,0};

    // Task 1
    int length=callEncrypt(prefix, 8, ciphertext);
    System.out.println("TASK 1: \n");
    System.out.println("Length of plaintext is "+ (length-8)+ " bytes.\n");
    System.out.println("The IV changes like this when we sequentially run encrypt 10 times: \n");
    for (int i = 0; i<10; i++) {
      callEncrypt(prefix, 0, ciphertext);
      System.out.println(byteArrayToHexString(getRecentIV()));
    }
    System.out.println("\nWe can see that the IV increases proportionally with the time (e.g. System.currentTimeMillis).\n");
    System.out.println("--------------------------------------------------------");
    System.out.println("\nTASK 2: \n \nStarting decryption of block 1 now. This might take a while.");

    // Task 2
    decryptFirstBlock();

    /*
  	for(int i=0; i<length; i++)
  	{
  	    System.out.print(String.format("%02x ", ciphertext[i]));
  	}
  	System.out.println("");
    */
  }

  // "framework" method to decrypt first block
  public static String decryptFirstBlock() throws Exception {
    byte[] knownPlaintext = new byte[]{0,0,0,0,0,0,0,0};
    for (int i=0; i<knownPlaintext.length; i++) {
      getCToMatch(i+1);
      System.out.println("\nTesting different m for m_"+(i+1)+":");
      byte m_i = getMi(knownPlaintext);
      if (i==(knownPlaintext.length-1)) { // last m in block, no need to shift known message to left
        knownPlaintext[knownPlaintext.length-1] = m_i;
      } else {
        appendAtArrayTailAndShiftRestLeft(knownPlaintext, m_i);
      }
    }
    String plaintext = new String(knownPlaintext);
    System.out.println("\n \nThe plaintext of the first block is: \"" + plaintext + "\"!");
    return plaintext;
  }

  // moves all elements in an byte array one index to the left
  // and appends newByte at tail (caution: arr[0] gets lost!)
  public static void appendAtArrayTailAndShiftRestLeft(byte[] arr, byte newByte) {
    arr[arr.length-1] = newByte;
    for (int i = 0; i < arr.length-1; i++) {
      arr[i] = arr[i+1];
    }
    arr[arr.length-1] = 0;
  }

  // generate cipher c for message at position mPos #
  // (i.e., choose mPos=1 if we try to find m_1, and so on)
  // and save it in global var "cToMatch"
  public static void getCToMatch(int mPos) throws Exception {
    boolean match = false;
    int tries = 0;
    while(!match) {
      tries++;
      int prefixLength = 8 - mPos;
      byte[] prefix = new byte[prefixLength];
      byte[] guessIV = guessIV();
      System.arraycopy(guessIV, 0, prefix, 0, prefixLength);
      callEncrypt(prefix, prefixLength, ciphertext);
      if (areFirstNBytesEqual(guessIV, getRecentIV(), 8)) {
        System.arraycopy(ciphertext, 8, cToMatch, 0, 8);
        System.arraycopy(guessIV, 0, ivForC, 0, 8);
        match = true;
      }
    }
  }

  // find m_i via exhaustive search until match for "cToMatch" is found
  public static byte getMi(byte[] knownMessage) throws Exception {
    int prefixLength = 8;
    byte mTry = Byte.MAX_VALUE;
    boolean match = false;
    byte[] knownMessageWithIV = new byte[8];
    while (!match) {
      System.arraycopy(knownMessage, 0, knownMessageWithIV, 0, 8);
      knownMessageWithIV[7] = mTry;
      xorArr1BytewiseWhereNotZero(knownMessageWithIV, ivForC);
      byte[] guessIV = guessIV();
      byte[] prefix = xorArraysBytewise(knownMessageWithIV, guessIV);
      callEncrypt(prefix, prefixLength, ciphertext);
      if (areFirstNBytesEqual(guessIV, getRecentIV(), 8)) {
        // IVs match - yay :)
        byte[] cFromGuess = new byte[8];
        System.arraycopy(ciphertext, 8, cFromGuess, 0, 8);
        if (areFirstNBytesEqual(cFromGuess, cToMatch, 8)) {
          System.out.println("\nFound the correct byte for m: "+ String.format("%02x ",mTry)+".");
          match = true;
        } else {
          if (mTry == Byte.MIN_VALUE){
            System.out.print("\nHmm, I tried them all but none matched. Something is wrong.");
          }
          mTry--;
          System.out.print(String.format("%02x ",mTry)+" ");
        }
      }
    }
    return mTry;
  }

  // helper method to xor the bytes from arr1 with the respective bytes in arr2
  public static byte[] xorArraysBytewise(byte[] arr1, byte[] arr2) {
    byte[] xorArray = new byte[arr1.length];
    for (int i = 0; i<arr1.length; i++) {
      xorArray[i] = (byte) (arr1[i] ^ arr2[i]);
    }
    return xorArray;
  }

  // helper method to xor the bytes from arr1 with the respective bytes in arr2
  // as long as the byte in arr1 is not zero
  public static void xorArr1BytewiseWhereNotZero(byte[] arr1, byte[] arr2) {
    for (int i = 0; i<arr1.length; i++) {
      if (arr1[i]!=0) {
        arr1[i] = (byte) (arr1[i] ^ arr2[i]);
      }
    }
  }

  // helper method to check if two arrays have the same fist n elements
  public static boolean areFirstNBytesEqual(byte[] arr1, byte[] arr2, int n) {
    if (arr1.length < n | arr2.length < n) return false;
    for (int i = 0; i < n; i++) {
      if (arr1[i]!=arr2[i]) return false;
    }
    return true;
  }

  // returns a guess for IV based on the latest observed IV
  // and the time that has passed since
  public static byte[] guessIV() throws Exception {
    long currentTime = System.currentTimeMillis();
    long addToRecentIV = (currentTime-time)+3;
    return addLongToByteArray(getRecentIV(), addToRecentIV);
  }

  // returns the IV of the most recent encryption,
  // i.e. the first 8 bytes of global ciphertext var
  public static byte[] getRecentIV() throws Exception {
      byte[] iv = new byte[8];
      System.arraycopy(ciphertext, 0, iv, 0, 8);
      return iv;
  }

  // helper method to simplify printing byte arrays as hex string
  public static String byteArrayToHexString(byte[] arr) {
    String bytesAsString = "0x";
    for(int i=0; i<arr.length; i++)
    {
        bytesAsString += String.format("%02x", arr[i]);
    }
    return bytesAsString;
  }

  // helper method to add a long value to a byte array and return the byte array
  public static byte[] addLongToByteArray(byte[] bytes, long summand) {
    long bytesAsLong = byteArrayToLong(bytes);
    long sum = bytesAsLong + summand;
    byte[] sumBytes = longToBytes(sum);
    return sumBytes;
  }

  // helper method to turn long value into byte array
  public static byte[] longToBytes(long x){
    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.putLong(x);
    return buffer.array();
  }

  // helper method to turn byte array into long value
  public static long byteArrayToLong(byte[] bytes) {
    return Long.decode(byteArrayToHexString(bytes));
  }

  // a helper method to call the external programme "encrypt" in the current directory
  // the parameters are the plaintext, length of prefix, and ciphertext; returns length of ciphertext
  static int callEncrypt(byte[] prefix, int prefix_len, byte[] ciphertext) throws IOException {
  	HexBinaryAdapter adapter = new HexBinaryAdapter();
  	Process process;
    time = System.currentTimeMillis();

  	// run the external process (don't bother to catch exceptions)
  	if(prefix != null)
  	{
  	    // turn prefix byte array into hex string
  	    byte[] p=Arrays.copyOfRange(prefix, 0, prefix_len);
  	    String PString=adapter.marshal(p);
  	    process = Runtime.getRuntime().exec("./encrypt "+PString);
  	}
  	else
  	{
  	    process = Runtime.getRuntime().exec("./encrypt");
  	}

  	// process the resulting hex string
  	String CString = (new BufferedReader(new InputStreamReader(process.getInputStream()))).readLine();
  	byte[] c=adapter.unmarshal(CString);
  	System.arraycopy(c, 0, ciphertext, 0, c.length);
  	return(c.length);
  }
}
