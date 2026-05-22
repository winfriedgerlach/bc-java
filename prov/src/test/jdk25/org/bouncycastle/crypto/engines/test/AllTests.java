package org.bouncycastle.crypto.engines.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Crypto Engines Tests (JDK 25)");
        suite.addTestSuite(ChaChaVectorTest.class);
        return suite;
    }
}