package com.github.marschall.hardwareacceleratedsha;

public class Cpuid {

  public static void main(String[] args) {
    int i = Integer.parseInt("29C6FBF", 16);
    for (int j = 0; j < 32; j++) {
      System.out.println(j + ": " + ((i >> j) & 1));
    }
    System.out.println(Integer.toBinaryString(i));
  }

}
