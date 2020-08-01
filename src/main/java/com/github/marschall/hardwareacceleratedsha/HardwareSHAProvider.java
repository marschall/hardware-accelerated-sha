package com.github.marschall.hardwareacceleratedsha;

import java.security.Provider;

/**
 * A security provider that installs one random number generation
 * algorithms that use the <a href="https://en.wikipedia.org/wiki/RdRand">RDAND</a>
 * and <code>RDSEED</code> hardware instructions.
 *
 * @see <a href="https://docs.oracle.com/javase/9/security/howtoimplaprovider.htm#JSSEC-GUID-C485394F-08C9-4D35-A245-1B82CDDBC031">How to Implement a Provider in the Java Cryptography Architecture</a>
 */
public final class HardwareSHAProvider extends Provider {

  /**
   * The name of this security provider.
   */
  public static final String NAME = "rdrand";

  /**
   * The name algorithm that uses the {@code RDRAND} and {@code RDSEED} hardware instructions.
   */
  public static final String ALGORITHM = "SHA-1";

  private static final long serialVersionUID = 1L;

  /**
   * Default constructor, either called directly by programmatic registration or
   * by JCA.
   */
  public HardwareSHAProvider() {
    super(NAME, 0.2d, "rdrand (SecureRandom)");
    this.put("MessageDigest." + ALGORITHM, HardwareSHA.class.getName());
    this.put("MessageDigest." + ALGORITHM + " ImplementedIn", "Hardware");
  }

}
