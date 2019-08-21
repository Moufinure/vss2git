/* Copyright 2009 HPDI, LLC
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Text;
using System.Security.Cryptography;
using Nito.KitchenSink.CRC;
using Hpdi.HashLib;

namespace Hpdi.HashTest
{
    /// <summary>
    /// Simple test program for CRC generation.
    /// </summary>
    /// <author>Trevor Robinson</author>
    class Program
    {
        static void Main(string[] args)
        {
            byte[] data = Encoding.ASCII.GetBytes("123456789");

            Crc16 crc16 = new Crc16(Crc16.IBM, true);
            Console.WriteLine("CRC-16 = {0:X4}", crc16.Compute(data));
            HashAlgorithm hash16 = new CRC16();
            Console.WriteLine("Nito CRC-16 = {0:X4}", BitConverter.ToUInt16(hash16.ComputeHash(data), 0));

            Crc16 crc16ccitt = new Crc16(Crc16.CCITT, false, 0xFFFF, 0);
            Console.WriteLine("CRC-16-CCITT = {0:X4}", crc16ccitt.Compute(data));
            HashAlgorithm hash16ccitt = new CRC16(CRC16.Definition.CcittFalse);
            Console.WriteLine("Nito CRC-16-CCITT = {0:X4}", BitConverter.ToUInt16(hash16ccitt.ComputeHash(data), 0));

            Crc32 crc32 = new Crc32(Crc32.IEEE, 0xFFFFFFFF, 0xFFFFFFFF);
            Console.WriteLine("CRC-32 = {0:X8}", crc32.Compute(data));
            HashAlgorithm hash32 = new CRC32();
            Console.WriteLine("Nito CRC-32 = {0:X8}", BitConverter.ToUInt32(hash32.ComputeHash(data), 0));

            XorHash32To16 xor1632 = new XorHash32To16(new Crc32(Crc32.IEEE));
            Console.WriteLine("Xor32To16 CRC-32 IEEE = {0:X4}", xor1632.Compute(data));
            CRC32.Definition crcdef = new CRC32.Definition();
            crcdef.FinalXorValue = 0x0;
            crcdef.Initializer = 0x0;
            crcdef.ReverseDataBytes = CRC32.Definition.Default.ReverseDataBytes;
            crcdef.ReverseResultBeforeFinalXor = CRC32.Definition.Default.ReverseResultBeforeFinalXor;
            crcdef.TruncatedPolynomial = CRC32.Definition.Default.TruncatedPolynomial;
            HashAlgorithm hashXor = new Xor32To16Algorithm(crcdef.Create());
            Console.WriteLine("Nito Xor32To16 CRC-32 = {0:X4}", BitConverter.ToUInt16(hashXor.ComputeHash(data), 0));
#if DEBUG
            Console.WriteLine("---> Program finished.");
            Console.ReadKey();
#endif
        }
    }
}
