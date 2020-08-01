package com.github.marschall.hardwareacceleratedsha;

import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.util.Arrays;

public final class HardwareSHA extends MessageDigestSpi {

  /**
   * Size of the digest in bytes.
   */
  private static final int DIGEST_SIZE = 160 / 8;

  /**
   * The block size in bytes.
   */
  private static final int BLOCK_SIZE = 64;

  private long bytesWritten;

  private final byte[] block;

  private final int[] state;

  /**
   * Index of the next write in {@code #block}.
   */
   private int blockIndex;

  public HardwareSHA() {
    this.block = new byte[BLOCK_SIZE];
    this.blockIndex = 0;
    this.bytesWritten = 0L;
    this.state = new int[5];
  }

  @Override
  protected int engineGetDigestLength() {
    return DIGEST_SIZE;
  }

  @Override
  protected void engineUpdate(byte input) {
    // TODO Auto-generated method stub

  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    // TODO Auto-generated method stub

  }

  @Override
  protected int engineDigest(byte[] buf, int offset, int len) throws DigestException {
    if (offset < 0) {
      throw new IllegalArgumentException("negative offset");
    }
    if (len < DIGEST_SIZE) {
      throw new IllegalArgumentException("buffer too small");
    }
    // TODO Auto-generated method stub
    return super.engineDigest(buf, offset, len);
  }

  @Override
  protected byte[] engineDigest() {
    // TODO Auto-generated method stub
    return null;
  }

  private void processBlock() {
    processBlock0(this.block, 0, this.state);
    this.blockIndex = 0;
  }

  @Override
  protected void engineReset() {
    Arrays.fill(this.block, (byte) 0);
    this.bytesWritten = 0L;
    this.blockIndex = 0;
  }

  private static native void processBlock0(byte[] input, int offset, int[] state);

  private static native boolean isSupported0();

}
