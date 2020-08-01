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
    if (this.blockIndex == 15) {
      this.processBlock();
    }
    this.block[this.blockIndex++] = input;
    this.bytesWritten += 1;
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    if (this.blockIndex == 15) {
      this.processBlock();
    }
    // fill the remainder of the buffer
    if (this.blockIndex != 0) {
    }
    // avoid array copies to the buffer, directly hash the input instead
    // copy the rest, by definition less than a block
  }

  @Override
  protected int engineDigest(byte[] buf, int offset, int len) throws DigestException {
    if (offset < 0) {
      throw new DigestException("negative offset");
    }
    if (len < DIGEST_SIZE) {
      throw new DigestException("buffer too small");
    }
    if ((buf.length - offset) < DIGEST_SIZE) {
      throw new DigestException("buffer overflow");
    }
    // TODO Auto-generated method stub
    copyState(this.state, buf, offset);
    return DIGEST_SIZE;
  }

  @Override
  protected byte[] engineDigest() {
    // TODO Auto-generated method stub
    byte[] digest = new byte[DIGEST_SIZE];
    copyState(this.state, digest, 0);
    return digest;
  }
  
  private static void copyState(int[] state, byte[] digest, int offset) {
    int i0 = state[0];
    digest[0] = (byte) (i0 >>> 24);
    digest[1] = (byte) ((i0 >>> 16) & 0xFF);
    digest[2] = (byte) ((i0 >>> 8) & 0xFF);
    digest[3] = (byte) (i0 & 0xFF);
    
    int i1 = state[1];
    digest[4] = (byte) (i1 >>> 24);
    digest[5] = (byte) ((i1 >>> 16) & 0xFF);
    digest[6] = (byte) ((i1 >>> 8) & 0xFF);
    digest[7] = (byte) (i1 & 0xFF);
    
    int i2 = state[2];
    digest[8] = (byte) (i2 >>> 24);
    digest[9] = (byte) ((i2 >>> 16) & 0xFF);
    digest[10] = (byte) ((i2 >>> 8) & 0xFF);
    digest[11] = (byte) (i2 & 0xFF);
    
    int i3 = state[3];
    digest[12] = (byte) (i3 >>> 24);
    digest[13] = (byte) ((i3 >>> 16) & 0xFF);
    digest[14] = (byte) ((i3 >>> 8) & 0xFF);
    digest[15] = (byte) (i3 & 0xFF);
    
    int i4 = state[4];
    digest[16] = (byte) (i4 >>> 24);
    digest[17] = (byte) ((i4 >>> 16) & 0xFF);
    digest[18] = (byte) ((i4 >>> 8) & 0xFF);
    digest[19] = (byte) (i4 & 0xFF);
  }

  private void processBlock() {
    int success = processBlock0(this.block, 0, this.state);
    if (success != 0) {
      throw new UncheckedDigestException("SHA-1 calculation failed");
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
  
  static boolean isSupported() {
    return isSupported0();
  }

  private static native boolean isSupported0();

}
