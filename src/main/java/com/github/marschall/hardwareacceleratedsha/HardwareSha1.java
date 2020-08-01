package com.github.marschall.hardwareacceleratedsha;

import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.util.Arrays;

/**
 * 
 * @see <a href="https://software.intel.com/content/www/us/en/develop/articles/intel-sha-extensions.html">New Instructions Supporting the Secure Hash Algorithm on Intel® Architecture Processors</a>
 * @see <a href="https://en.wikipedia.org/wiki/Intel_SHA_extensions">Intel SHA extensions</a>
 *
 */
public final class HardwareSha1 extends MessageDigestSpi {
  
  // https://github.com/noloader/SHA-Intrinsics

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

  public HardwareSha1() {
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
    if (Math.addExact(offset, DIGEST_SIZE) > buf.length) {
      throw new IllegalArgumentException("buffer overflow");
    }
    // TODO Auto-generated method stub
    return super.engineDigest(buf, offset, len);
  }

  @Override
  protected byte[] engineDigest() {
    // TODO Auto-generated method stub
    return null;
  }

  private void processBlock() throws DigestException {
    int success = processBlock0(this.block, 0, this.state);
    if (success != 0) {
      throw new DigestException("SHA-1 calculation failed");
    }
    this.blockIndex = 0;
  }

  @Override
  protected void engineReset() {
    Arrays.fill(this.block, (byte) 0);
    this.bytesWritten = 0L;
    this.blockIndex = 0;
  }

  private static native int processBlock0(byte[] input, int offset, int[] state);

  private static native boolean isSupported0();

}
