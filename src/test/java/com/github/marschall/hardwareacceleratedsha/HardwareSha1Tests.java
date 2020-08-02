package com.github.marschall.hardwareacceleratedsha;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class HardwareSha1Tests {

  @ParameterizedTest
  @MethodSource("messageDigests")
  void singleByte(MessageDigest messageDigest) {
  }

  @ParameterizedTest
  @MethodSource("messageDigests")
  void oneBlock(MessageDigest messageDigest) {
  }

  @ParameterizedTest
  @MethodSource("messageDigests")
  void multipleBlocks(MessageDigest messageDigest) {
  }

  static Stream<MessageDigest> messageDigests() throws NoSuchAlgorithmException {
    return Stream.of(MessageDigest.getInstance("SHA-1"));
  }

}
