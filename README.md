

Digests a one 64 byte block in single JNI call. This includes message scheduling and all 80 rounds.

The thread is at a save point for most of the time.

- copy the 5 32 bit state values to the stack
- copy the 64 byte block to the stack
- copy the 5 32 bit state values from the stack

This means the Java `byte[]` does not have to be pinned, the GC can move the object and the JVM does not have to copy the values to the native heap.
