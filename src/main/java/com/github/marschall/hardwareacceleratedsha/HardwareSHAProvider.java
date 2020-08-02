package com.github.marschall.hardwareacceleratedsha;

import java.security.Provider;

/**
 * A security provider that installs message digests that are hardware
 * accelerated.
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/11/security/howtoimplaprovider.html#GUID-C485394F-08C9-4D35-A245-1B82CDDBC031">How to Implement a Provider in the Java Cryptography Architecture</a>
 */
public final class HardwareSHAProvider extends Provider {
  
  // TODO supported check on deserialization

  /**
   * The name of this security provider.
   */
  public static final String NAME = "hw-sha";

  /**
   * The name of the SHA-1 digest.
   */
  public static final String ALGORITHM_SHA1 = "SHA-1";

  private static final long serialVersionUID = 1L;

  /**
   * Default constructor, either called directly by programmatic registration or
   * by JCA.
   */
  public HardwareSHAProvider() {
    super(NAME, 0.2d, "hardware accelerated SHA (MessageDisgest)");
    if (HardwareSha1.isSupported()) {
      this.put("MessageDigest." + ALGORITHM_SHA1, HardwareSha1.class.getName());
      this.put("MessageDigest." + ALGORITHM_SHA1 + " ImplementedIn", "Hardware");
    }
  }

}
