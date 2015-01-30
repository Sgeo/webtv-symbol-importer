## IDA Symbol Importer for WebTV (MSNTV) Builds

This is a basic Python script allowing you to reverse engineer WebTV builds by reading one of the three types of WebTV symbol files into IDA.  It assigns names to classes, functions and variables provided you've properly loaded a WebTV build into IDA and have the correct symbol file.

I created this so I could study the hardware of the older WebTV boxes in an attempt to build a MIPS Linux build that will run on these boxes.  These boxes were discontinued September 2013 by Microsoft and are fairly cheap to purchase.

**NOTE:** Microsoft used a proprietary operating system on their older MIPS-based WebTV boxes.  This script wont work for Windows CE images used on the UltimateTV and the MSNTV2.  It's possible that you could use this on an UltimateTV's bootrom image since it used the propritary operating system but I don't have a symbol file to test.

Builds for boxes I know should work:

- **WebTV Classic v2**: INT-W150, MAT-965, RW-2100
- **WebTV Plus v1**: INT-200, INT-W200B, MAT-972, SIS-100, RW-2000, RW-2001
- **Japan**: INT-WJ200, INT-WJ300
- **WebTV Plus v2**: RW-2110, INT-W250, MAT-976
- **Dish Network**: Dishplayer 7100, Dishplayer 7200

This script was also used to help out a buddy of mine build a custom WebTV build.  You can find details here: http://turdinc.kicks-ass.net/Msntv/WebTV-MAME/echostar.html