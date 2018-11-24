import java.util.Random;
import java.io.*;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Arrays;


class DESPrac
{
    public static void main(String[] args) throws IOException
    {
        long testP=0x1234567887654321L;
        long testK=0x33333333333333L;


        // Task 1
        /*
        // Encrypt testPlaintext with testKey
        long testC = TwoRoundModifiedDES(testK, testP);
        System.out.println("Feisteled this cipher: \n \n \n "+Long.toHexString(testC));

        // Perform 1000 encryption and meassure runtime
        long timeStart = System.nanoTime();
        for (int i =0; i < 1000; i++) {
          TwoRoundModifiedDES(testK, testP);
        }
        long endTime = System.nanoTime();

        BigInteger timeDiffInNanoSeconds = BigInteger.valueOf(endTime-timeStart);
        BigInteger nanosToSeconds = BigInteger.valueOf(1000000000);
        BigInteger secondsToYears = BigInteger.valueOf(60*60*24*365);

        long numAttacks = (long) Math.pow(2,55);
        BigInteger totalTime= BigInteger.valueOf(numAttacks).multiply(timeDiffInNanoSeconds).divide(BigInteger.valueOf(1000));
        System.out.println("total time before divide : "+totalTime);
        totalTime = totalTime.divide(nanosToSeconds);
        totalTime = totalTime.divide(secondsToYears);
        System.out.println("numAttacks: "+numAttacks);
        System.out.println("nanosToSeconds: "+nanosToSeconds);
        System.out.println("secondsToYears: "+secondsToYears);
        System.out.println("totalTime: "+totalTime);
        System.out.println("Took "+timeDiffInNanoSeconds+" ns to perform 1000 encryptions.");
        System.out.println("An exhaustion attack for a key of size 56 bit takes 2^55 tries on average. Thus, we'd expect it to take around "+totalTime+" years to break our cipher.");
        */

        // Task 2

        //differentialDistributionTable(2);

        //Task 3

	       //getE1Diff(0x60000000);
         //getE1Diff(0x02000000L);
	       reduceOptionsForKn("a");

         // TASK 4
         reduceOptionsForKn("b");




         /* Code used to find InputDiff and OutputDiff for Task 4
         long DeltaO = 0b111;
         DeltaO = DeltaO << 24;
         System.out.println(Long.toBinaryString(DeltaO));
         long DeltaF = PBox(DeltaO);
         System.out.println(Long.toBinaryString(DeltaF));
         long DeltaR = DeltaF ^ (0x40004010);
         System.out.println(Long.toHexString(DeltaR));
         */

    }

    static void getE1Diff (long DeltaR) {
      long E1Delta = EBox(DeltaR);
      long E1DeltaA = (E1Delta>>42);
      long E1DeltaB = (E1Delta>>36);
      System.out.println(Long.toBinaryString(E1DeltaA));
      System.out.println(Long.toBinaryString(E1DeltaB));
    }

    static void reduceOptionsForKn(String n) throws IOException {
      Random prng = new Random();
      int numTries = 0;

      // Initialization depends on for which subkey n we want to reduce options
      int SBoxNumber;
      byte inputDiff;
      byte outputDiff;
      long DeltaP;
      int bitwiseMoveForEn;
      long hittingDiff;
      if (n.equals("a")) {
        SBoxNumber = 1;
        inputDiff = 0x0C;
        outputDiff = 0xD;
        DeltaP = 0x0080800260000000L;
        hittingDiff = 0x0000000060000000L;
        bitwiseMoveForEn = 42;
      } else {
        SBoxNumber = 2;
        inputDiff = 0b100;
        outputDiff = 0b111;
        DeltaP = 0x4000401002000000L;
        hittingDiff = 0x0000000002000000L;
        bitwiseMoveForEn = 36;
      }

      // Initally, all values between 0 and 64 could be the 6-bit subkey Kn
      HashSet<Byte> options = new HashSet<Byte>();
      for (byte i = 0; i<0x20; i++) {
        options.add(i);
      }

      // Find all inputs of the respective SBox that match inputDiff->outputDif
      int[] PI = getPossibleInputs(SBoxNumber, inputDiff, outputDiff);

      //for(int b: PI) {
      //  System.out.println(b);
      //}

      // Try encrypting random P's to reduce options for subkey Kn
      while(options.size()>2 && numTries<100) {
        numTries++;
        long P = prng.nextLong();
        long P_=P^DeltaP;
        long C = callEncrypt(P);
        long C_ = callEncrypt(P_);
        long CC_Diff = C_^C;

        //Hitting the characteristic
        if (CC_Diff==hittingDiff) {

          // Compute E1n from R0
          long R0=P&MASK32;
          long E1 = EBox(R0);
          long E1n = (E1 >> bitwiseMoveForEn) & 0b111111;
          //System.out.println(Long.toBinaryString(E1)+ " => "+ Long.toBinaryString(E1n));

          // Generate all possible keys (for all i in PIi: E1n ^ PIi)
          int[] pkForP = new int[PI.length];
          for (int i = 0; i<PI.length; i++) {
            pkForP[i] = (int)E1n ^ PI[i];
          }

          // remove all keys from options that are not in list of possible keys
          HashSet<Byte> toRemove = new HashSet<Byte>();
          for (Byte option : options) {
            boolean optionInPK = Arrays.stream(pkForP).anyMatch(i -> i == option);
            if (!optionInPK && options.contains(option)) {
              toRemove.add(option);
            }
          }
          for (byte option : toRemove) {
            options.remove(option);
          }
        }
      }
      // Print all final options for Kn
      System.out.println("Narrowed options for K_"+n+" down to: ");
      for (Byte option : options) {
        System.out.println(Integer.toBinaryString(option));
      }
    }

    static int[] getPossibleInputs(int SBoxNumber, byte inputDiff, byte outputDiff) {
      byte[] STable = S1Table;
      switch (SBoxNumber) {
          case 1:  STable = S1Table;
                   break;
          case 2:  STable = S2Table;
                   break;
          case 3:  STable = S3Table;
                   break;
          case 4:  STable = S4Table;
                   break;
          case 5:  STable = S5Table;
                   break;
          case 6:  STable = S6Table;
                   break;
          case 7:  STable = S7Table;
                   break;
          case 8:  STable = S8Table;
                   break;
      }

      HashSet<Integer> possibleInputs = new HashSet<Integer>();
      for (int input = 0; input < 64; input++) {
        int input_ = input^inputDiff;
        int out = STable[input]^STable[input_];
        if (out == outputDiff) {
          possibleInputs.add(input);
        }
      }

      int[] PI = new int[possibleInputs.size()];
      int i = 0;
      for (int pi : possibleInputs) {
        PI[i] = pi;
        i++;
      }
      return PI;
    }

    static int[][] differentialDistributionTable (int SBoxNumber)
    {
        byte[] STable = S1Table;
        switch (SBoxNumber) {
            case 1:  STable = S1Table;
                     break;
            case 2:  STable = S2Table;
                     break;
            case 3:  STable = S3Table;
                     break;
            case 4:  STable = S4Table;
                     break;
            case 5:  STable = S5Table;
                     break;
            case 6:  STable = S6Table;
                     break;
            case 7:  STable = S7Table;
                     break;
            case 8:  STable = S8Table;
                     break;
        }

        int[][] distributionTable = new int[64][16];
        for (int inputDiff = 0; inputDiff<64; inputDiff++){
          for (int input = 0; input<64; input++) {
            int pairedInput = input^inputDiff;
            byte output1 = STable[input];
            byte output2 = STable[pairedInput];
            int outputDiff = output1^output2;
            distributionTable[inputDiff][outputDiff]++;
          }
        }
        for (int inputDiff = 0; inputDiff<64; inputDiff++){
          for (int outputDiff = 0; outputDiff<16; outputDiff++) {
            if (inputDiff==0b100) {
              // Can be used to visualize differential distribution for Task 4
              //System.out.println("THIS > "+outputDiff+" ");
            }
            System.out.print(distributionTable[inputDiff][outputDiff]+" ");
          }
          System.out.println();
        }
        return distributionTable;
        // get set of pairs for differentials (should be 64 pairs)
        // for each output diff, add num of pairs with respective differential
    }

    // constants for &-ing with, to mask off everything but the bottom 32- or 48-bits of a long
    static long MASK32 = 0xffffffffL;
    static long MASK48 = 0xffffffffffffL;

    static long TwoRoundModifiedDES(long K, long P) // input is a 56-bit key "long" and a 64-bit plaintext "long", returns the ciphertext
    {
        long L0=(P>>32)&MASK32; // watch out for the sign extension!
        long R0=P&MASK32;
        long K1=K&MASK48;
        long K2=(K>>8)&MASK48;

        long L1=R0;
        long R1=L0^Feistel(R0, K1);

        long L2=R1;
        long R2=L1^Feistel(R1, K2);

        long C=L2<<32 | R2;

        return(C);
    }

    static long Feistel(long R, long K) // input is a 32-bit integer and 48-bit key, both stored in 64-bit signed "long"s; returns the output of the Feistel round
    {
        long F;
        //  Expansion
        F = EBox(R);
        // xor with key
        F = F ^ K;
        // S-boxes
        F = SBox(F);
        // P boxes
        F = PBox(F);
        // xor with 32-bits subkey
        long subkey = K&MASK32;
        F = F ^ subkey;

        return(F);
    }

    // NB: these differ from the tables in the DES standard because the latter are encoded in a strange order

    static final byte[] S1Table={
     3,  7,  5,  1, 12,  8,  2, 11, 10,  3, 15,  6,  7, 12,  8,  2,
    13,  0, 11,  4,  6,  5,  1, 14,  0, 10,  4, 13,  9, 15, 14,  9,
     4,  1,  2, 12, 11, 14, 15,  5, 14,  7,  8,  3,  1,  8,  5,  6,
     9, 15, 12, 10,  0, 11, 10,  0, 13,  4,  7,  9,  6,  2,  3, 11,
    };

    static final byte[] S2Table={
    13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
    10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
     7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
     0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11,
    };

    static final byte[] S3Table={
    14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
     3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
     4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
    15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13,
    };

    static final byte[] S4Table={
    10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
     1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
    13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
    11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12,
    };

    static final byte[] S5Table={
     7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
     1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
    10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
    15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14,
    };

    static final byte[] S6Table={
     2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
     8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
     4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
    15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3,
    };

    static final byte[] S7Table={
    12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
     0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
     9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
     7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13,
    };

    static final byte[] S8Table={
     4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
     3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
     1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
    10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12,
    };

    // STables[i-1][s] is the output for input s to S-box i
    static final byte[][] STables={S1Table, S2Table, S3Table, S4Table, S5Table, S6Table, S7Table, S8Table};

    static long SBox(long S) // input is a 48-bit integer stored in 64-bit signed "long"
    {
        // Split I into eight 6-bit chunks
        int Sa=(int)((S>>42));
        int Sb=(int)((S>>36)&63);
        int Sc=(int)((S>>30)&63);
        int Sd=(int)((S>>24)&63);
        int Se=(int)((S>>18)&63);
        int Sf=(int)((S>>12)&63);
        int Sg=(int)((S>>6)&63);
        int Sh=(int)(S&63);
        // Apply the S-boxes
        byte Oa=S1Table[Sa];
        byte Ob=S2Table[Sb];
        byte Oc=S3Table[Sc];
        byte Od=S4Table[Sd];
        byte Oe=S5Table[Se];
        byte Of=S6Table[Sf];
        byte Og=S7Table[Sg];
        byte Oh=S8Table[Sh];
        // Combine answers into 32-bit output stored in 64-bit signed "long"
        long O=(long)Oa<<28 | (long)Ob<<24 | (long)Oc<<20 | (long)Od<<16 | (long)Oe<<12 | (long)Of<<8 | (long)Og<<4 | (long)Oh;
        return(O);
    }

    static long EBox(long R) // input is a 32-bit integer stored in 64-bit signed "long"
    {
        // compute each 6-bit component
        long Ea=(R>>27)&31 | (R&1)<<5;
        long Eb=(R>>23)&63;
        long Ec=(R>>19)&63;
        long Ed=(R>>15)&63;
        long Ee=(R>>11)&63;
        long Ef=(R>>7)&63;
        long Eg=(R>>3)&63;
        long Eh=(R>>31)&1 | (R&31)<<1;
        // 48-bit output stored in 64-bit signed "long"
        long E=(long)Ea<<42 | (long)Eb<<36 | (long)Ec<<30 | (long)Ed<<24 | (long)Ee<<18 | (long)Ef<<12 | (long)Eg<<6 | (long)Eh;
        return(E);
    }

    static final int[] Pbits={
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
    };

    // this would have been a lot faster as fixed binary operations rather than a loop
    static long PBox(long O) // input is a 32-bit integer stored in 64-bit signed "long"
    {
        long P=0L;
        for(int i=0; i<32; i++)
        {
            P|=((O>>(32-Pbits[i]))&1) << (31-i);
        }
        return(P);
    }

    // a helper method to call the external programme "desencrypt" in the current directory
    // the parameter is the 64-bit plaintext to encrypt, returns the ciphertext
    static long callEncrypt(long P) throws IOException
    {
        Process process = Runtime.getRuntime().exec("./desencrypt "+Long.toHexString(P));
        String CString = (new BufferedReader(new InputStreamReader(process.getInputStream()))).readLine();

        // we have to go via BigInteger otherwise the signed longs cause incorrect parsing
        long C=new BigInteger(CString, 16).longValue();

        return(C);
    }

}
