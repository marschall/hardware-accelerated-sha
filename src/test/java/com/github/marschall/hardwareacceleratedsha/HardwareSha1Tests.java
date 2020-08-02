package com.github.marschall.hardwareacceleratedsha;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class HardwareSha1Tests {

  private static final String ALGORITHM = "SHA-1";

  @ParameterizedTest
  @MethodSource("messageDigests")
  void singleByte(MessageDigest messageDigest) {
    messageDigest.update((byte) 1);
    byte[] digest = messageDigest.digest();
    byte[] expected = new byte[] {-65, -117, 69, 48, -40, -46, 70, -35, 116, -84, 83, -95, 52, 113, -69, -95, 121, 65, -33, -9};
    assertArrayEquals(expected, digest);
  }

  @ParameterizedTest
  @MethodSource("messageDigests")
  void reset(MessageDigest messageDigest) {
    messageDigest.update((byte) 1);
    messageDigest.reset();
    messageDigest.update((byte) 1);
    byte[] digest = messageDigest.digest();
    byte[] expected = new byte[] {-65, -117, 69, 48, -40, -46, 70, -35, 116, -84, 83, -95, 52, 113, -69, -95, 121, 65, -33, -9};
    assertArrayEquals(expected, digest);
  }

  @ParameterizedTest
  @MethodSource("messageDigests")
  void targetDigest(MessageDigest messageDigest) throws DigestException {
    messageDigest.update((byte) 1);
    byte[] digest = new byte[22];
    Arrays.fill(digest, (byte) 1);
    messageDigest.digest(digest, 1, 20);
    byte[] expected = new byte[] {1, -65, -117, 69, 48, -40, -46, 70, -35, 116, -84, 83, -95, 52, 113, -69, -95, 121, 65, -33, -9, 1};
    assertArrayEquals(expected, digest);
  }

  @ParameterizedTest
  @MethodSource("messageDigests")
  void oneBlockNoOffset(MessageDigest messageDigest) {
    byte[] message = new byte[64];
    for (int i = 0; i < message.length; i++) {
      message[i] = (byte) i;
    }
    messageDigest.update(message);
    byte[] digest = messageDigest.digest();
    byte[] expected = new byte[] {-58, 19, -115, 81, 79, -6, 33, 53, -65, -50, 14, -48, -72, -6, -58, 86, 105, -111, 126, -57};
    assertArrayEquals(expected, digest);
  }

  @ParameterizedTest
  @MethodSource("messageDigests")
  void oneBlockWithOffset(MessageDigest messageDigest) {
    byte[] message = new byte[66];
    for (int i = 0; i < message.length; i++) {
      message[i] = (byte) (i - 1);
    }
    messageDigest.update(message, 1, 64);
    byte[] digest = messageDigest.digest();
    byte[] expected = new byte[] {-58, 19, -115, 81, 79, -6, 33, 53, -65, -50, 14, -48, -72, -6, -58, 86, 105, -111, 126, -57};
    assertArrayEquals(expected, digest);
  }

  @ParameterizedTest
  @MethodSource("messageDigests")
  void multipleBlocks(MessageDigest messageDigest) {
    messageDigest.update((byte) 1);
    byte[] message = new byte[65];
    for (int i = 0; i < message.length; i++) {
      message[i] = (byte) (i + 2);
    }
    messageDigest.update((byte) 1);
    messageDigest.update(message);
    byte[] digest = messageDigest.digest();
    byte[] expected = new byte[] {29, -114, 67, 75, 8, 44, 109, -63, -107, -125, -111, 120, -52, 57, -29, -31, -50, -115, -37, -104};
    assertArrayEquals(expected, digest);
  }

  @ParameterizedTest
  @MethodSource("messageDigests")
  void getAlgorithm(MessageDigest messageDigest) {
    assertEquals(ALGORITHM, messageDigest.getAlgorithm());
  }

  @ParameterizedTest
  @MethodSource("messageDigests")
  void getDigestLength(MessageDigest messageDigest) {
    assertEquals(20, messageDigest.getDigestLength());
  }

  static Stream<MessageDigest> messageDigests() throws NoSuchAlgorithmException {
    return Stream.of(MessageDigest.getInstance(ALGORITHM));
  }

}
